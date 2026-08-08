// Sentinel triage agent — core infrastructure.
//
// Deploys a Python Function App with a system-assigned identity, and grants that
// identity the minimum roles it needs on the Sentinel workspace. The workspace
// may live in a different resource group (or subscription) from this deployment.
//
// The timer trigger works the moment this finishes. The event-driven playbook is
// opt-in via deployPlaybook, because it needs one extra object id that has to be
// looked up in the tenant (see deploy.sh).

targetScope = 'resourceGroup'

// --------------------------------------------------------------------------- //
// Parameters
// --------------------------------------------------------------------------- //

@description('Base name for the deployed resources. Lowercase letters and digits.')
@minLength(3)
@maxLength(16)
param baseName string = 'sentineltriage'

@description('Location for the deployed resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace that Microsoft Sentinel is enabled on.')
param sentinelWorkspaceName string

@description('Resource group containing the Sentinel workspace.')
param sentinelResourceGroup string

@description('Subscription containing the Sentinel workspace. Defaults to this subscription.')
param sentinelSubscriptionId string = subscription().subscriptionId

@description('CRON expression for the polling timer. Default: every 15 minutes. NCRONTAB has a leading seconds field.')
param pollSchedule string = '0 */15 * * * *'

@description('How far back each poll looks for new incidents. KQL timespan, e.g. 4h.')
param pollLookback string = '4h'

@description('Start in dry-run mode: triage runs and logs, but nothing is written to incidents.')
param dryRun bool = true

@description('Narrative provider. Rules-only triage works fully with "none".')
@allowed([
  'none'
  'azure_openai'
  'anthropic'
])
param llmProvider string = 'none'

@description('Azure OpenAI deployment name, or the Claude model id, depending on llmProvider.')
param llmModel string = ''

@description('Azure OpenAI endpoint, e.g. https://my-aoai.openai.azure.com. Only used for azure_openai.')
param llmEndpoint string = ''

@description('Anthropic API key. Stored in Key Vault and referenced, never written to app settings in clear text. Only used for anthropic.')
@secure()
param anthropicApiKey string = ''

@description('Also assign Log Analytics Reader on the workspace. Needed for the KQL enrichment queries on most workspaces.')
param assignLogAnalyticsReader bool = true

@description('Deploy the Logic App playbook and the Sentinel automation rule for near-real-time triage.')
param deployPlaybook bool = false

@description('Object id of the Azure Security Insights service principal in this tenant. Required when deployPlaybook is true; deploy.sh looks it up.')
param securityInsightsPrincipalId string = ''

@description('Resource id of the workspace to send Function telemetry to. Defaults to the Sentinel workspace; point elsewhere to keep operational logs out of your security data.')
param appInsightsWorkspaceResourceId string = ''

@description('Tags applied to every resource.')
param tags object = {
  workload: 'sentinel-triage-agent'
}

// --------------------------------------------------------------------------- //
// Names and derived values
// --------------------------------------------------------------------------- //

var suffix = uniqueString(resourceGroup().id, baseName)
// Storage account names are capped at 24 characters and allow only lowercase
// alphanumerics, so the base name is truncated rather than assumed to fit.
var storageName = toLower('${take(replace(baseName, '-', ''), 11)}${take(suffix, 11)}st')
var functionAppName = '${baseName}-func-${take(suffix, 6)}'
var planName = '${baseName}-plan-${take(suffix, 6)}'
var insightsName = '${baseName}-ai-${take(suffix, 6)}'
// Key Vault names are 3-24 chars, must start with a letter and must not end
// with a hyphen. A fixed prefix plus uniqueString satisfies all three whatever
// baseName happens to be.
var keyVaultName = 'kv-${uniqueString(resourceGroup().id, baseName, 'secrets')}'
// Versionless secret URI, composed rather than read back from the resource, so
// no conditionally-deployed resource is dereferenced unconditionally.
var anthropicSecretUri = 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets/anthropic-api-key/'

var sentinelWorkspaceResourceId = resourceId(
  sentinelSubscriptionId,
  sentinelResourceGroup,
  'Microsoft.OperationalInsights/workspaces',
  sentinelWorkspaceName
)

var telemetryWorkspaceId = empty(appInsightsWorkspaceResourceId)
  ? sentinelWorkspaceResourceId
  : appInsightsWorkspaceResourceId

var needsKeyVault = llmProvider == 'anthropic' && !empty(anthropicApiKey)

// --------------------------------------------------------------------------- //
// Storage, telemetry, hosting
// --------------------------------------------------------------------------- //

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    defaultToOAuthAuthentication: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: insightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: telemetryWorkspaceId
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: planName
  location: location
  tags: tags
  // Y1 is the Linux Consumption plan: no idle cost, and available in every
  // region Functions is available in.
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  kind: 'functionapp'
  properties: {
    reserved: true // Linux
  }
}

// --------------------------------------------------------------------------- //
// Key Vault (only when an Anthropic key was supplied)
// --------------------------------------------------------------------------- //

// Everything conditional lives inside the module, so main.bicep never
// dereferences a resource that may not have been deployed.
module secrets 'modules/keyvault.bicep' = if (needsKeyVault) {
  name: 'triage-secrets'
  params: {
    keyVaultName: keyVaultName
    location: location
    tags: tags
    secretName: 'anthropic-api-key'
    secretValue: anthropicApiKey
    readerPrincipalId: functionApp.identity.principalId
  }
}

// --------------------------------------------------------------------------- //
// Function App
// --------------------------------------------------------------------------- //

var storageConnectionString = 'DefaultEndpointsProtocol=https;AccountName=${storage.name};AccountKey=${storage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'

var baseAppSettings = [
  {
    name: 'FUNCTIONS_EXTENSION_VERSION'
    value: '~4'
  }
  {
    name: 'FUNCTIONS_WORKER_RUNTIME'
    value: 'python'
  }
  {
    name: 'AzureWebJobsStorage'
    value: storageConnectionString
  }
  {
    name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
    value: storageConnectionString
  }
  {
    name: 'WEBSITE_CONTENTSHARE'
    value: toLower(functionAppName)
  }
  {
    name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
    value: insights.properties.ConnectionString
  }
  // Oryx builds the Python dependencies from requirements.txt server-side on
  // zip deploy, so nothing has to be vendored into the package.
  {
    name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
    value: 'true'
  }
  {
    name: 'ENABLE_ORYX_BUILD'
    value: 'true'
  }
  // --- triage agent configuration ---
  {
    name: 'AZURE_SUBSCRIPTION_ID'
    value: sentinelSubscriptionId
  }
  {
    name: 'SENTINEL_RESOURCE_GROUP'
    value: sentinelResourceGroup
  }
  {
    name: 'SENTINEL_WORKSPACE_NAME'
    value: sentinelWorkspaceName
  }
  {
    name: 'TRIAGE_POLL_SCHEDULE'
    value: pollSchedule
  }
  {
    name: 'TRIAGE_POLL_LOOKBACK'
    value: pollLookback
  }
  {
    name: 'TRIAGE_POLL_ENABLED'
    value: 'true'
  }
  {
    name: 'TRIAGE_DRY_RUN'
    value: string(dryRun)
  }
  {
    name: 'TRIAGE_LLM_PROVIDER'
    value: llmProvider
  }
  {
    name: 'TRIAGE_LLM_MODEL'
    value: llmModel
  }
  {
    name: 'TRIAGE_LLM_ENDPOINT'
    value: llmEndpoint
  }
]

var anthropicKeySetting = needsKeyVault
  ? [
      {
        name: 'ANTHROPIC_API_KEY'
        value: '@Microsoft.KeyVault(SecretUri=${anthropicSecretUri})'
      }
    ]
  : []

resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    reserved: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      appSettings: concat(baseAppSettings, anthropicKeySetting)
    }
  }
}

// --------------------------------------------------------------------------- //
// RBAC on the Sentinel workspace (may be a different resource group)
// --------------------------------------------------------------------------- //

module workspaceRbac 'modules/rbac.bicep' = {
  name: 'triage-workspace-rbac'
  scope: resourceGroup(sentinelSubscriptionId, sentinelResourceGroup)
  params: {
    workspaceName: sentinelWorkspaceName
    principalId: functionApp.identity.principalId
    assignLogAnalyticsReader: assignLogAnalyticsReader
  }
}

// --------------------------------------------------------------------------- //
// Optional: Logic App playbook + Sentinel automation rule
// --------------------------------------------------------------------------- //

module playbook 'modules/playbook.bicep' = if (deployPlaybook) {
  name: 'triage-playbook'
  params: {
    baseName: baseName
    location: location
    tags: tags
    functionAppName: functionApp.name
    functionAppResourceId: functionApp.id
    sentinelWorkspaceName: sentinelWorkspaceName
    sentinelResourceGroup: sentinelResourceGroup
    sentinelSubscriptionId: sentinelSubscriptionId
    securityInsightsPrincipalId: securityInsightsPrincipalId
  }
}

// --------------------------------------------------------------------------- //
// Outputs
// --------------------------------------------------------------------------- //

output functionAppName string = functionApp.name
output functionAppHostName string = functionApp.properties.defaultHostName
output functionAppPrincipalId string = functionApp.identity.principalId
output healthUrl string = 'https://${functionApp.properties.defaultHostName}/api/health'
output storageAccountName string = storage.name
output applicationInsightsName string = insights.name
output keyVaultName string = needsKeyVault ? keyVaultName : ''
