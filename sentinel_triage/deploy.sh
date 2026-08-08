#!/usr/bin/env bash
#
# One-command deploy for the Sentinel triage agent.
#
#   ./deploy.sh -g rg-triage -w my-sentinel-workspace -r rg-sentinel
#
# Provisions the infrastructure, publishes the function code, and verifies the
# result. Safe to re-run: every resource is named deterministically and the
# deployment is incremental.
#
# Prerequisites: Azure CLI (logged in), zip. The az CLI installs the Bicep
# compiler on first use.

set -euo pipefail

RESOURCE_GROUP=""
WORKSPACE_NAME=""
WORKSPACE_RG=""
WORKSPACE_SUB=""
LOCATION=""
BASE_NAME="sentineltriage"
DRY_RUN="true"
LLM_PROVIDER="none"
LLM_MODEL=""
LLM_ENDPOINT=""
DEPLOY_PLAYBOOK="false"
POLL_SCHEDULE="0 */15 * * * *"
SKIP_CODE="false"
SKIP_INFRA="false"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE'
Usage: ./deploy.sh -g <resource-group> -w <workspace-name> [options]

Required:
  -g, --resource-group    Resource group to deploy the agent into (created if absent)
  -w, --workspace         Name of the Log Analytics workspace Sentinel runs on

Options:
  -r, --workspace-rg      Resource group of the Sentinel workspace (default: same as -g)
  -s, --workspace-sub     Subscription of the Sentinel workspace (default: current)
  -l, --location          Azure region (default: the resource group's region)
  -n, --name              Base name for resources (default: sentineltriage)
      --live              Deploy in live mode. Without this the agent starts in
                          dry run: it triages and logs but writes nothing.
      --llm <provider>    none | azure_openai | anthropic (default: none)
      --llm-model <name>  AOAI deployment name, or a Claude model id
      --llm-endpoint <url> Azure OpenAI endpoint
      --playbook          Also deploy the Logic App playbook + automation rule
                          for near-real-time triage
      --schedule <ncron>  Polling schedule (default: "0 */15 * * * *")
      --skip-infra        Publish code only
      --skip-code         Provision infrastructure only
  -h, --help              Show this help

Set ANTHROPIC_API_KEY in the environment when using --llm anthropic; it is
written to Key Vault and referenced from app settings, never stored in clear.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--resource-group) RESOURCE_GROUP="$2"; shift 2 ;;
    -w|--workspace) WORKSPACE_NAME="$2"; shift 2 ;;
    -r|--workspace-rg) WORKSPACE_RG="$2"; shift 2 ;;
    -s|--workspace-sub) WORKSPACE_SUB="$2"; shift 2 ;;
    -l|--location) LOCATION="$2"; shift 2 ;;
    -n|--name) BASE_NAME="$2"; shift 2 ;;
    --live) DRY_RUN="false"; shift ;;
    --llm) LLM_PROVIDER="$2"; shift 2 ;;
    --llm-model) LLM_MODEL="$2"; shift 2 ;;
    --llm-endpoint) LLM_ENDPOINT="$2"; shift 2 ;;
    --playbook) DEPLOY_PLAYBOOK="true"; shift ;;
    --schedule) POLL_SCHEDULE="$2"; shift 2 ;;
    --skip-infra) SKIP_INFRA="true"; shift ;;
    --skip-code) SKIP_CODE="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$RESOURCE_GROUP" || -z "$WORKSPACE_NAME" ]]; then
  echo "Error: --resource-group and --workspace are required." >&2
  usage
  exit 1
fi

command -v az >/dev/null 2>&1 || { echo "Error: the Azure CLI (az) is required." >&2; exit 1; }
command -v zip >/dev/null 2>&1 || { echo "Error: zip is required to package the function." >&2; exit 1; }

WORKSPACE_RG="${WORKSPACE_RG:-$RESOURCE_GROUP}"
WORKSPACE_SUB="${WORKSPACE_SUB:-$(az account show --query id -o tsv)}"

echo "==> Signed in as: $(az account show --query user.name -o tsv) (subscription $(az account show --query name -o tsv))"

# --------------------------------------------------------------------------- #
# Preflight: fail here rather than a third of the way through a deployment
# --------------------------------------------------------------------------- #

echo "==> Checking the Sentinel workspace is reachable"
if ! az monitor log-analytics workspace show \
      --subscription "$WORKSPACE_SUB" \
      --resource-group "$WORKSPACE_RG" \
      --workspace-name "$WORKSPACE_NAME" -o none 2>/dev/null; then
  echo "Error: workspace '$WORKSPACE_NAME' not found in resource group '$WORKSPACE_RG'" >&2
  echo "       (subscription $WORKSPACE_SUB). Check --workspace-rg / --workspace-sub." >&2
  exit 1
fi

if [[ "$LLM_PROVIDER" == "azure_openai" && -z "$LLM_ENDPOINT" ]]; then
  echo "Error: --llm azure_openai also needs --llm-endpoint and --llm-model." >&2
  exit 1
fi

ANTHROPIC_KEY_ARG=()
if [[ "$LLM_PROVIDER" == "anthropic" ]]; then
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "Error: --llm anthropic requires ANTHROPIC_API_KEY in the environment." >&2
    exit 1
  fi
  ANTHROPIC_KEY_ARG=("anthropicApiKey=$ANTHROPIC_API_KEY")
  LLM_MODEL="${LLM_MODEL:-claude-opus-5}"
fi

# The Sentinel service principal's object id is tenant-specific, so it has to be
# resolved rather than hardcoded. Its application id is well known and constant.
SECURITY_INSIGHTS_OBJECT_ID=""
if [[ "$DEPLOY_PLAYBOOK" == "true" ]]; then
  echo "==> Resolving the Azure Security Insights service principal"
  SECURITY_INSIGHTS_OBJECT_ID="$(az ad sp show \
    --id 98785600-1bb7-4fb9-b9fa-19afe2c8a360 \
    --query id -o tsv 2>/dev/null || true)"
  if [[ -z "$SECURITY_INSIGHTS_OBJECT_ID" ]]; then
    echo "Warning: could not resolve the Security Insights service principal." >&2
    echo "         The playbook will deploy, but Sentinel will not be able to run it" >&2
    echo "         until you grant permissions in the portal:" >&2
    echo "         Sentinel > Automation > Playbook permissions > Configure permissions." >&2
  else
    echo "    object id: $SECURITY_INSIGHTS_OBJECT_ID"
  fi
fi

# --------------------------------------------------------------------------- #
# Infrastructure
# --------------------------------------------------------------------------- #

if [[ "$SKIP_INFRA" != "true" ]]; then
  if ! az group show --name "$RESOURCE_GROUP" -o none 2>/dev/null; then
    if [[ -z "$LOCATION" ]]; then
      echo "Error: resource group '$RESOURCE_GROUP' does not exist, so --location is required." >&2
      exit 1
    fi
    echo "==> Creating resource group $RESOURCE_GROUP in $LOCATION"
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o none
  fi
  LOCATION="${LOCATION:-$(az group show --name "$RESOURCE_GROUP" --query location -o tsv)}"

  echo "==> Deploying infrastructure (dry_run=$DRY_RUN, llm=$LLM_PROVIDER, playbook=$DEPLOY_PLAYBOOK)"
  az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --name "sentinel-triage-$(date +%Y%m%d%H%M%S)" \
    --template-file "$SCRIPT_DIR/infra/main.bicep" \
    --parameters \
      baseName="$BASE_NAME" \
      location="$LOCATION" \
      sentinelWorkspaceName="$WORKSPACE_NAME" \
      sentinelResourceGroup="$WORKSPACE_RG" \
      sentinelSubscriptionId="$WORKSPACE_SUB" \
      pollSchedule="$POLL_SCHEDULE" \
      dryRun="$DRY_RUN" \
      llmProvider="$LLM_PROVIDER" \
      llmModel="$LLM_MODEL" \
      llmEndpoint="$LLM_ENDPOINT" \
      deployPlaybook="$DEPLOY_PLAYBOOK" \
      securityInsightsPrincipalId="$SECURITY_INSIGHTS_OBJECT_ID" \
      "${ANTHROPIC_KEY_ARG[@]}" \
    -o none
fi

FUNCTION_APP="$(az deployment group list \
  --resource-group "$RESOURCE_GROUP" \
  --query "[?starts_with(name, 'sentinel-triage-')] | sort_by(@, &properties.timestamp)[-1].properties.outputs.functionAppName.value" \
  -o tsv 2>/dev/null || true)"

if [[ -z "$FUNCTION_APP" || "$FUNCTION_APP" == "null" ]]; then
  FUNCTION_APP="$(az functionapp list --resource-group "$RESOURCE_GROUP" \
    --query "[?starts_with(name, '$BASE_NAME')].name | [0]" -o tsv)"
fi

if [[ -z "$FUNCTION_APP" ]]; then
  echo "Error: could not determine the Function App name." >&2
  exit 1
fi
echo "==> Function App: $FUNCTION_APP"

# --------------------------------------------------------------------------- #
# Application code
# --------------------------------------------------------------------------- #

if [[ "$SKIP_CODE" != "true" ]]; then
  PACKAGE="$(mktemp -d)/triage.zip"
  echo "==> Packaging $SCRIPT_DIR/app"
  (
    cd "$SCRIPT_DIR/app"
    # Ship the config alongside the code so the agent finds it without an extra
    # mount or app setting.
    if [[ -f "$SCRIPT_DIR/config/triage.yaml" && ! -f triage.yaml ]]; then
      cp "$SCRIPT_DIR/config/triage.yaml" triage.yaml
      TEMP_CONFIG=1
    fi
    zip -qr "$PACKAGE" . \
      -x '*.pyc' -x '__pycache__/*' -x '*/__pycache__/*' \
      -x '.venv/*' -x 'local.settings.json' -x '.pytest_cache/*'
    if [[ "${TEMP_CONFIG:-0}" == "1" ]]; then rm -f triage.yaml; fi
  )
  echo "    package: $(du -h "$PACKAGE" | cut -f1)"

  echo "==> Publishing (server-side build; this takes a couple of minutes)"
  az functionapp deployment source config-zip \
    --resource-group "$RESOURCE_GROUP" \
    --name "$FUNCTION_APP" \
    --src "$PACKAGE" \
    --build-remote true \
    -o none
  rm -rf "$(dirname "$PACKAGE")"
fi

# --------------------------------------------------------------------------- #
# Verify
# --------------------------------------------------------------------------- #

HEALTH_URL="https://${FUNCTION_APP}.azurewebsites.net/api/health"
echo "==> Waiting for the app to come up: $HEALTH_URL"

STATUS=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  STATUS="$(curl -fsS --max-time 20 "$HEALTH_URL" 2>/dev/null || true)"
  if [[ -n "$STATUS" ]]; then
    break
  fi
  echo "    not ready yet (attempt $attempt/10), waiting 15s"
  sleep 15
done

echo
if [[ -n "$STATUS" ]]; then
  echo "Deployment complete. Health check says:"
  echo "  $STATUS"
else
  echo "Deployment finished, but the health endpoint did not respond in time."
  echo "Cold starts on Consumption can exceed this window. Check again with:"
  echo "  curl $HEALTH_URL"
  echo "and inspect logs with:"
  echo "  az webapp log tail -g $RESOURCE_GROUP -n $FUNCTION_APP"
fi

echo
if [[ "$DRY_RUN" == "true" ]]; then
  cat <<EOF
The agent is running in DRY RUN: it triages incidents and logs the verdict, but
writes nothing back to Sentinel. Watch a few cycles, then switch it on with:

  az functionapp config appsettings set -g $RESOURCE_GROUP -n $FUNCTION_APP \\
    --settings TRIAGE_DRY_RUN=false
EOF
else
  echo "The agent is LIVE and will comment on and label incidents."
fi

echo
echo "Follow it with:  az webapp log tail -g $RESOURCE_GROUP -n $FUNCTION_APP"
