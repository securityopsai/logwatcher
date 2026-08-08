// Role assignments for the triage agent, scoped to the Sentinel workspace.
//
// Deployed into the workspace's resource group, which may differ from the one
// holding the Function App. Scoping to the workspace resource rather than the
// resource group keeps the grant to exactly the data the agent triages.

targetScope = 'resourceGroup'

@description('Name of the Log Analytics workspace Sentinel is enabled on.')
param workspaceName string

@description('Principal id of the identity to grant access to.')
param principalId string

@description('Also assign Log Analytics Reader (needed for the KQL enrichment queries on most workspaces).')
param assignLogAnalyticsReader bool = true

// Microsoft Sentinel Responder: read incidents, and update them (labels,
// comments, severity, status). Notably it does NOT allow editing analytics
// rules, connectors or workbooks.
var sentinelResponderRoleId = '3e150937-b8fe-4cfb-8069-0eaf05ecd056'

// Log Analytics Reader: read-only access to the workspace's data plane, which
// is what the enrichment queries run against.
var logAnalyticsReaderRoleId = '73c42c96-874c-492b-b04d-ab87d138a893'

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource responder 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: workspace
  name: guid(workspace.id, principalId, sentinelResponderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      sentinelResponderRoleId
    )
    principalId: principalId
    // Setting this explicitly avoids the replication race where a freshly
    // created managed identity is not yet visible to the RBAC service.
    principalType: 'ServicePrincipal'
  }
}

resource logsReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (assignLogAnalyticsReader) {
  scope: workspace
  name: guid(workspace.id, principalId, logAnalyticsReaderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      logAnalyticsReaderRoleId
    )
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}

output workspaceResourceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
