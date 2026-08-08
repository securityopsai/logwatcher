"""Optional LLM narrative layer.

The rule engine owns the verdict. An LLM, when configured, does two things and
nothing else:

1. Writes the analyst-facing narrative.
2. May *dissent* — and dissent is one-directional. It can raise a verdict toward
   needs-review, never lower one toward false positive. A model that is wrong in
   the escalating direction costs an analyst a few minutes; wrong in the other
   direction it closes a real intrusion.

Providers are behind :class:`LLMProvider` so the agent code is identical whether
the deployment runs rules-only, Azure OpenAI, or Claude.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from .config import TriageConfig
from .models import Disposition, Enrichment, Incident, Verdict

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a SOC analyst assistant writing the triage note for a Microsoft Sentinel \
incident. A deterministic rule engine has already produced the verdict; it is \
authoritative and you do not restate or re-derive it.

Write for the next analyst who opens this incident. Lead with what happened and \
what it means, then what to check. Be specific about the entities and evidence \
you were given. Do not speculate beyond the evidence, do not invent host names, \
IPs, timestamps or log sources, and do not recommend a tool the analyst was not \
told they have.

Set `disagrees` to true only when the evidence points to this being MORE serious \
than the rule engine concluded. If you think the engine over-reacted, say so in \
the narrative but leave `disagrees` false — under-escalation is the expensive \
mistake here.\
"""

RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["narrative", "next_steps", "disagrees", "dissent_reason"],
    "properties": {
        "narrative": {
            "type": "string",
            "description": "2-5 sentences for the analyst. Plain prose, no headings.",
        },
        "next_steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Up to 4 concrete investigative actions, most useful first.",
        },
        "disagrees": {
            "type": "boolean",
            "description": "True only if the evidence suggests the incident is more serious than the verdict.",
        },
        "dissent_reason": {
            "type": "string",
            "description": "Why you disagree, or an empty string when disagrees is false.",
        },
    },
}


@dataclass
class Narrative:
    """What the LLM layer returns."""

    text: str
    next_steps: List[str] = field(default_factory=list)
    disagrees: bool = False
    dissent_reason: str = ""
    provider: str = "none"
    error: Optional[str] = None


class LLMProvider(Protocol):
    """Anything that can turn triage context into a narrative."""

    name: str

    def generate(self, prompt: str) -> Narrative: ...


# --------------------------------------------------------------------------- #
# Prompt assembly
# --------------------------------------------------------------------------- #


def build_prompt(incident: Incident, enrichment: Enrichment, verdict: Verdict) -> str:
    """Render the triage context the model reasons over.

    Only facts that were actually gathered go in. Enrichment queries that failed
    are named explicitly so the model treats them as unknown rather than absent.
    """
    lines: List[str] = []
    lines.append("## Incident")
    lines.append(f"Number: {incident.number}")
    lines.append(f"Title: {incident.title}")
    lines.append(f"Severity: {incident.severity}   Status: {incident.status}")
    if incident.alert_rule_names:
        lines.append(f"Analytics rules: {', '.join(incident.alert_rule_names[:5])}")
    if incident.tactics:
        lines.append(f"MITRE tactics: {', '.join(incident.tactics)}")
    lines.append(f"Alerts in incident: {incident.alert_count}")
    if incident.description:
        lines.append(f"Description: {incident.description[:1200]}")

    if incident.entities:
        lines.append("")
        lines.append("## Entities")
        for entity in incident.entities[:25]:
            lines.append(f"- {entity.kind.value}: {entity.value}")

    lines.append("")
    lines.append("## Verdict from the rule engine (authoritative)")
    lines.append(f"Disposition: {verdict.disposition.value}")
    lines.append(f"Suspicion score: {verdict.score:.0f}/100")
    lines.append(f"Confidence: {verdict.confidence:.0f}/100")
    if verdict.signals:
        lines.append("Contributing signals:")
        for signal in verdict.top_signals():
            sign = "+" if signal.points > 0 else ""
            lines.append(f"- [{sign}{signal.points:g}] {signal.name}: {signal.detail}")

    lines.append("")
    lines.append("## Enrichment")
    history = enrichment.rule_history
    if history is not None and history.closed:
        lines.append(
            f"- Rule history: {history.closed} closed incidents, "
            f"{history.fp_rate:.0%} were false/benign positive"
        )
    if enrichment.prior_closures:
        lines.append(
            f"- {len(enrichment.prior_closures)} prior incident(s) with the same rule "
            "and entities were closed as not actionable"
        )
    if enrichment.related_incidents:
        related = ", ".join(f"#{r.incident_number}" for r in enrichment.related_incidents[:5])
        lines.append(f"- Open incidents sharing entities: {related}")
    for hit in enrichment.threat_intel[:5]:
        lines.append(
            f"- Threat intel match: {hit.entity} ({hit.threat_type or 'unclassified'},"
            f" source {hit.source or 'unknown'})"
        )
    for entity, prevalence in list(enrichment.ip_prevalence.items())[:5]:
        lines.append(
            f"- {entity}: seen {prevalence.events} times over "
            f"{prevalence.distinct_days} distinct days in this workspace"
        )
    if enrichment.failures:
        lines.append(
            "- Could not evaluate (treat as unknown, not as absent): "
            + ", ".join(sorted(enrichment.failures))
        )
    if len(lines) and lines[-1] == "## Enrichment":
        lines.append("- No enrichment data was available.")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


class NullProvider:
    """Default: no LLM call. The agent falls back to a templated narrative."""

    name = "none"

    def generate(self, prompt: str) -> Narrative:  # noqa: ARG002 - interface
        return Narrative(text="", provider=self.name)


def _parse_response(payload: str, provider: str) -> Narrative:
    """Parse the model's JSON response into a :class:`Narrative`."""
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError) as exc:
        return Narrative(
            text="",
            provider=provider,
            error=f"Model returned unparseable JSON: {exc}",
        )
    if not isinstance(data, dict):
        return Narrative(text="", provider=provider, error="Model response was not an object")

    steps = data.get("next_steps") or []
    if not isinstance(steps, list):
        steps = []
    return Narrative(
        text=str(data.get("narrative") or "").strip(),
        next_steps=[str(s).strip() for s in steps if str(s).strip()][:4],
        disagrees=bool(data.get("disagrees")),
        dissent_reason=str(data.get("dissent_reason") or "").strip(),
        provider=provider,
    )


class AnthropicProvider:
    """Claude via the official Anthropic SDK.

    ``ANTHROPIC_API_KEY`` is read from the environment by the SDK. In Azure,
    populate it from Key Vault via a Function App setting reference.
    """

    name = "anthropic"

    def __init__(self, config: TriageConfig) -> None:
        settings = config.llm
        self.model = settings.get("model") or "claude-opus-5"
        self.max_tokens = int(settings.get("max_tokens", 4096))
        self.effort = str(settings.get("effort", "low"))
        self.timeout = int(settings.get("timeout_seconds", 45))

    def generate(self, prompt: str) -> Narrative:
        import anthropic

        client = anthropic.Anthropic(timeout=float(self.timeout))
        try:
            response = client.beta.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                # SOC content routinely brushes the cyber safety classifiers;
                # server-side fallback keeps a benign triage note from being lost
                # to a refusal.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                output_config={
                    "effort": self.effort,
                    "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
                },
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIStatusError as exc:
            return Narrative(text="", provider=self.name, error=f"Anthropic API error: {exc}")
        except anthropic.APIConnectionError as exc:
            return Narrative(text="", provider=self.name, error=f"Anthropic unreachable: {exc}")

        # A refusal returns HTTP 200 with empty or partial content; reading
        # content[0] unconditionally would raise here.
        if response.stop_reason == "refusal":
            category = getattr(getattr(response, "stop_details", None), "category", None)
            return Narrative(
                text="",
                provider=self.name,
                error=f"Model declined to respond (category: {category or 'unspecified'})",
            )

        text = next((b.text for b in response.content if b.type == "text"), "")
        if not text:
            return Narrative(text="", provider=self.name, error="Model returned no text")
        return _parse_response(text, self.name)


class AzureOpenAIProvider:
    """Azure OpenAI via managed identity, over the REST API.

    Uses the same credential as the Sentinel client, so there is no key to
    rotate. The deployment needs the *Cognitive Services OpenAI User* role on the
    Azure OpenAI resource.
    """

    name = "azure_openai"
    API_VERSION = "2024-10-21"
    SCOPE = "https://cognitiveservices.azure.com/.default"

    def __init__(self, config: TriageConfig, credential: Optional[Any] = None) -> None:
        settings = config.llm
        endpoint = (settings.get("endpoint") or "").rstrip("/")
        if not endpoint:
            raise ValueError("llm.endpoint (or TRIAGE_LLM_ENDPOINT) is required for azure_openai")
        self.endpoint = endpoint
        self.deployment = settings.get("model") or ""
        if not self.deployment:
            raise ValueError("llm.model (or TRIAGE_LLM_MODEL) must name the AOAI deployment")
        self.max_tokens = int(settings.get("max_tokens", 4096))
        self.temperature = float(settings.get("temperature", 0.0))
        self.timeout = int(settings.get("timeout_seconds", 45))
        self._credential = credential

    def _token(self) -> str:
        if self._credential is None:
            from .sentinel import default_credential

            self._credential = default_credential()
        return self._credential.get_token(self.SCOPE).token

    def generate(self, prompt: str) -> Narrative:
        import requests

        url = (
            f"{self.endpoint}/openai/deployments/{self.deployment}"
            f"/chat/completions?api-version={self.API_VERSION}"
        )
        body = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "triage_narrative",
                    "strict": True,
                    "schema": RESPONSE_SCHEMA,
                },
            },
        }
        try:
            response = requests.post(
                url,
                json=body,
                headers={
                    "Authorization": f"Bearer {self._token()}",
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return Narrative(text="", provider=self.name, error=f"Azure OpenAI unreachable: {exc}")

        if not response.ok:
            return Narrative(
                text="",
                provider=self.name,
                error=f"Azure OpenAI returned {response.status_code}: {response.text[:300]}",
            )

        try:
            choice = response.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            return Narrative(
                text="", provider=self.name, error=f"Unexpected Azure OpenAI response: {exc}"
            )
        return _parse_response(choice, self.name)


def build_provider(config: TriageConfig) -> LLMProvider:
    """Instantiate the configured provider, degrading to none on failure."""
    provider = str(config.llm.get("provider", "none")).strip().lower()
    if provider in ("", "none"):
        return NullProvider()
    try:
        if provider == "anthropic":
            if not os.environ.get("ANTHROPIC_API_KEY"):
                logger.warning("llm.provider is anthropic but ANTHROPIC_API_KEY is unset")
            return AnthropicProvider(config)
        if provider == "azure_openai":
            return AzureOpenAIProvider(config)
    except Exception as exc:  # noqa: BLE001 - a misconfigured LLM must not stop triage
        logger.error("Could not initialise LLM provider %r: %s", provider, exc)
        return NullProvider()

    logger.warning("Unknown llm.provider %r; running rules-only", provider)
    return NullProvider()


def apply_narrative(verdict: Verdict, narrative: Narrative) -> Verdict:
    """Fold the narrative into the verdict, honouring escalate-only dissent."""
    if narrative.error:
        logger.warning("LLM narrative unavailable: %s", narrative.error)
        return verdict
    if narrative.text:
        verdict.narrative = narrative.text
    if narrative.next_steps:
        verdict.rationale.append("Suggested next steps: " + "; ".join(narrative.next_steps))
    if narrative.disagrees and narrative.dissent_reason:
        verdict.llm_dissent = narrative.dissent_reason
        # Escalate only. A likely-true-positive verdict is already at the top.
        if verdict.disposition == Disposition.LIKELY_FALSE_POSITIVE:
            verdict.disposition = Disposition.NEEDS_REVIEW
            verdict.rationale.append(
                "Raised to needs-review: the narrative model disagreed with the "
                "false-positive verdict."
            )
    return verdict
