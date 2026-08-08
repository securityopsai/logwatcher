# Sentinel Triage Agent

An Azure-native triage agent for Microsoft Sentinel. It picks up new incidents,
gathers evidence with KQL, scores them with a deterministic rule engine, and
writes an explained triage note back onto the incident.

The verdict is always the rule engine's. It is explainable, unit-tested, and
costs nothing per incident. An LLM is optional and only writes the analyst-facing
prose — it can raise a verdict toward "needs review", never lower one.

```
Sentinel incident
      │
      ├─ enrich ──── KQL ──▶ rule FP history · prior closures for these entities
      │                      related open incidents · entity prevalence · threat intel
      │
      ├─ score ────────────▶ suspicion 0-100 + confidence 0-100, every point traced
      │                      to a named signal with its evidence
      │
      ├─ narrate ──────────▶ template, or Azure OpenAI / Claude when configured
      │
      └─ act ──────────────▶ Markdown comment + labels   (auto-close is opt-in, off)
```

---

## Try it before you deploy anything

The scoring path runs offline against a saved incident, so you can see what the
agent would say without touching Azure:

```bash
cd sentinel_triage
pip install -r app/requirements.txt

PYTHONPATH=app python -m triage.cli replay -c config/triage.yaml \
  tests/fixtures/incident-noisy-scanner.json \
  --enrichment tests/fixtures/enrichment-noisy-scanner.json \
  --show-comment
```

You get the verdict, every contributing signal with its evidence, and the exact
Markdown that would land on the incident:

```
#10472 'Suspicious authentication activity' -> LikelyFalsePositive (score 0, confidence 93)
  · Baseline 45 from incident severity Medium.
  · Score 0 <= 30 with confidence 93.

  Signals:
       -30  prior_fp_closure       2 prior incident(s) from this rule with the same entities
                                   (10.50.10.42, svc-vulnscan@corp.example) were closed as
                                   false/benign positive (e.g. #10201, #10388)
       -25  rule_fp_rate_high      94% historical non-actionable rate - 63 closed, 51 FP / 8 BTP / 3 TP
       -10  entity_very_common     every enriched entity is routine in this workspace
        -8  service_account        all involved accounts look like service/machine accounts
        +8  off_hours              activity at 2026-03-11 02:38 UTC falls outside business hours
        -5  internal_only_ips      all 1 IP entities are internal/non-routable
```

Drop `--enrichment` and the same incident comes back **NeedsReview** — with no
evidence gathered, the agent will not call anything a false positive. That
asymmetry is the core safety property, and it is tested.

---

## Deploy

```bash
./deploy.sh -g rg-triage -w my-sentinel-workspace -r rg-sentinel -l westeurope
```

That provisions everything, publishes the code, and polls the health endpoint
until the app answers. It is idempotent — re-run it after any change.

| Flag | Meaning |
| --- | --- |
| `-g` | Resource group for the agent (created if missing) |
| `-w` | Log Analytics workspace Sentinel runs on |
| `-r` | That workspace's resource group (defaults to `-g`) |
| `-s` | That workspace's subscription (defaults to current) |
| `--live` | Skip dry run and let it write to incidents immediately |
| `--playbook` | Also deploy the Logic App + automation rule for near-real-time triage |
| `--llm` | `none` (default), `azure_openai`, or `anthropic` |

**It starts in dry run.** The agent triages on schedule and logs full verdicts,
but writes nothing. Watch a few cycles, then:

```bash
az functionapp config appsettings set -g rg-triage -n <function-app> \
  --settings TRIAGE_DRY_RUN=false
```

Prerequisites: Azure CLI logged in, and rights to create resources in `-g` plus
assign roles on the workspace (Owner or User Access Administrator there).

### What gets created

| Resource | Why |
| --- | --- |
| Function App (Linux Consumption, Python 3.11) | Runs the agent. No idle cost. |
| Storage account | Functions runtime requirement |
| Application Insights | Verdict logs and failures |
| Two role assignments on the workspace | Microsoft Sentinel Responder + Log Analytics Reader, scoped to the one workspace |
| Key Vault | Only when `--llm anthropic` — holds the API key, referenced from app settings |
| Logic App + automation rule | Only with `--playbook` |

The agent authenticates with a system-assigned managed identity. There are no
credentials to rotate on the Sentinel side.

---

## Two ways it can be triggered

**Timer (default).** The Function polls Sentinel every 15 minutes for incidents
created in the last 4 hours. One Function App, one role assignment, no other
moving parts — it works the moment the deploy finishes.

**Playbook (`--playbook`).** A Sentinel automation rule fires a Logic App on
incident creation, which POSTs the incident's ARM id to the Function. Latency
drops from minutes to seconds. The Logic App's Sentinel connection uses managed
identity, so there is no OAuth consent step after deployment.

Both can run together; the label check keeps them from double-triaging.

Re-running is safe by construction. The comment id is derived from the incident,
so a re-run updates the same comment instead of stacking duplicates, and any
incident already carrying a `triage:` label is skipped.

---

## How the score works

Each incident starts at a baseline from its severity (Medium → 45), then every
signal that fires adds or subtracts points:

| De-escalating | | Escalating | |
| --- | ---: | --- | ---: |
| Entity on your allowlist | −30 | Entity matched in threat intel | +25 |
| Same rule + entity closed as FP before | −30 | Entity is in other open incidents | +20 |
| Rule is ≥80% historically non-actionable | −25 | Touches a high-value asset | +15 |
| Rule is ≥50% historically non-actionable | −12 | Alerts span ≥2 MITRE tactics | +12 |
| Entity is routine in this workspace | −10 | Rule is historically ≥50% true positive | +10 |
| All accounts look like service accounts | −8 | External IP with no prior history | +8 |
| All IPs are internal | −5 | Outside business hours | +8 |
| | | Many alerts grouped | +8 |

Score ≤ 30 → likely false positive. ≥ 70 → likely true positive. In between →
needs review.

**Confidence is separate and load-bearing.** It measures how much evidence
actually arrived: how many enrichment queries succeeded, whether the incident had
entities and a rule name, how much history the rule has. A false-positive verdict
requires confidence ≥ 60, so a workspace where the queries time out gets
"needs review" rather than a confident dismissal. Escalation is not gated this
way — being wrong toward "look at this" is cheap.

A failed enrichment query is recorded as a failure, not as an absence of
findings, and appears in the comment under **Evidence gaps**.

### The KQL

Enrichment queries live in [`app/triage/enrichment.py`](app/triage/enrichment.py).
Two details matter for correctness against a real workspace:

- `SecurityIncident` holds **one row per incident update**, not per incident. Every
  query collapses to the latest row per `IncidentNumber` with `arg_max` before
  counting — without that, one much-edited incident inflates the statistics.
- Optional tables are referenced through `union isfuzzy=true`, so a workspace that
  does not ingest `DeviceNetworkEvents` (or has the newer `ThreatIntelIndicators`
  rather than the legacy `ThreatIntelligenceIndicator`) degrades to "no rows"
  instead of a failing query.

Entity values reach KQL as JSON-escaped `dynamic([...])` literals, and the
config schema constrains table and column names to bare identifiers.

---

## Configuration

Everything is in [`config/triage.yaml`](config/triage.yaml), and every value has
a working default — the file only needs what you want to change. Validate before
deploying:

```bash
PYTHONPATH=app python -m triage.cli validate -c config/triage.yaml
```

The two things worth setting on day one:

```yaml
known_good:
  ip_ranges: [10.0.0.0/8, 203.0.113.64/26]   # your networks and egress NAT
  accounts: ['^svc-backup@corp\.example$']

suppressions:
  - name: nightly-vuln-scan
    reason: Qualys scanner, approved by IT ops, runs 02:00-04:00 daily
    rule_names: ['Suspicious authentication']
    entities:
      ip_ranges: [10.50.10.0/24]
```

A suppression is an operator decision rather than an inference: a match forces
the false-positive verdict at high confidence. Every condition you list must
match, and conditions you omit are ignored. Prefer these to lowering thresholds —
each one is named, reasoned, and greppable.

Deployment-specific knobs are app settings, so you can flip them without a
redeploy: `TRIAGE_DRY_RUN`, `TRIAGE_AUTO_CLOSE`, `TRIAGE_POLL_LOOKBACK`,
`TRIAGE_POLL_ENABLED`, `TRIAGE_LLM_PROVIDER`.

---

## Blast radius

By default the agent comments and labels. It never closes anything.

Auto-close is implemented and gated on **four independent conditions**, each of
which alone blocks it:

```yaml
actions:
  auto_close:
    enabled: false          # 1. off by default
    min_confidence: 85      # 2. confidence floor
    max_score: 20           # 3. score ceiling
    allowed_rules: []       # 4. empty means nothing is eligible
```

Plus a fifth: the narrative model can veto a closure by dissenting, even though
it cannot cause one. When a closure is blocked, the reason is recorded on the
incident so the skip is auditable.

The recommended path is dry run → comment-only → add one rule to
`allowed_rules` after watching its verdicts.

Severity is only ever *suggested* in the comment, never applied — analysts triage
by severity queue and an agent silently reordering it is unwelcome.

---

## The optional LLM layer

With `llm.provider: none` (the default) the agent is fully functional and writes
a deterministic narrative. Turning a provider on changes only the prose:

```bash
./deploy.sh -g rg-triage -w soc-ws --llm azure_openai \
  --llm-endpoint https://my-aoai.openai.azure.com --llm-model gpt-4o
```

Azure OpenAI uses the same managed identity (grant it *Cognitive Services OpenAI
User* on the AOAI resource — there is no key). Claude uses `ANTHROPIC_API_KEY`,
which `deploy.sh` puts in Key Vault and references from app settings.

The model returns structured output and may set `disagrees`. That can move a
`LikelyFalsePositive` up to `NeedsReview`; there is no code path from dissent to
a *less* serious verdict, and that is tested in both directions. If the call
fails, times out, or is refused, the verdict stands and the template narrative
is used.

---

## Development

```bash
pip install -r app/requirements.txt pytest
pytest                                   # 176 tests, no Azure needed
```

Against a live workspace:

```bash
export AZURE_SUBSCRIPTION_ID=... SENTINEL_RESOURCE_GROUP=... SENTINEL_WORKSPACE_NAME=...
az login

PYTHONPATH=app python -m triage.cli triage 10472 --dry-run --show-comment
PYTHONPATH=app python -m triage.cli poll --lookback 24h --dry-run
```

`DefaultAzureCredential` means your `az login` identity is used locally and the
managed identity in Azure, with no code change.

### Layout

```
app/                      the zip-deploy root
  function_app.py         timer, HTTP and health triggers
  triage/
    models.py             dataclasses: Incident, Signal, Verdict, Enrichment
    config.py             YAML/JSON loading, schema validation, env overrides
    sentinel.py           ARM incident REST + Log Analytics queries + parsing
    enrichment.py         the KQL
    rules.py              the scoring engine
    llm.py                pluggable narrative layer
    actions.py            comment rendering, labels, the auto-close gates
    agent.py              orchestration and the polling sweep
    cli.py                replay / triage / poll / validate
infra/                    Bicep: main + rbac, playbook, automation-rule modules
config/triage.yaml        the tunable configuration
tests/                    176 tests + replay fixtures
```

---

## Verification status

Honest about what has and has not been exercised:

- **Verified.** All 176 tests pass on Python 3.11. The offline replay runs
  end-to-end against the fixtures and produces the output shown above. The config
  schema, the CLI, and the Markdown rendering are exercised by tests.
- **Not verified by me.** The Bicep has not been deployed against a live
  subscription, and the KQL has not been run against a real workspace — no Azure
  subscription was reachable from where this was built. The CI workflow compiles
  the Bicep on every push, which catches syntax and reference errors but not
  quota, region, or policy failures. Run `deploy.sh` against a non-production
  workspace first, and check the **Evidence gaps** section of the first few
  comments — that is where a schema mismatch in your workspace will show up.

If a role definition id has drifted in your cloud (Sentinel Responder is
`3e150937-b8fe-4cfb-8069-0eaf05ecd056`), it is a single constant in
[`infra/modules/rbac.bicep`](infra/modules/rbac.bicep).

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Comments say every enrichment query failed | Role assignment has not propagated (wait ~5 min) or the workspace name/RG is wrong. Check `/api/health`. |
| `ip_prevalence` always fails | A configured table exists but the column does not. Fix `enrichment.ip_prevalence_sources`. |
| Everything comes back NeedsReview | Expected on a new workspace — the rule-history signals need closed incidents to learn from. Add `known_good` entries meanwhile. |
| Playbook deployed but never fires | Sentinel needs permission to run it: Sentinel → Automation → Playbook permissions → Configure permissions. `deploy.sh` grants this automatically when it can resolve the service principal. |
| Timer never runs | Check `TRIAGE_POLL_ENABLED` and that `TRIAGE_POLL_SCHEDULE` is NCRONTAB — it has a **leading seconds field**, so every 15 minutes is `0 */15 * * * *`. |

Logs: `az webapp log tail -g <rg> -n <function-app>`, or query
`traces | where message contains "->"` in Application Insights for the verdict
line of every triaged incident.
