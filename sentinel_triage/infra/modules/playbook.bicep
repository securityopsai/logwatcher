// Optional near-real-time path: Sentinel automation rule -> Logic App -> Function.
//
// The Logic App exists only to bridge Sentinel's automation rules (which can
// only invoke playbooks) to the Function that does the work. It passes the
// incident's ARM id and nothing else; the Function re-fetches the incident so
// triage always runs against canonical data.
//
// The API connection authenticates with the Logic App's managed identity
// (parameterValueType: 'Alternative'), which is what makes this deployable end
// to end — the usual OAuth consent click in the portal is not needed.

targetScope = 'resourceGroup'

param baseName string
param location string
param tags object

@description('Name of the Function App to invoke.')
param functionAppName string

@description('Resource id of the Function App to invoke.')
param functionAppResourceId string

param sentinelWorkspaceName string
param sentinelResourceGroup string
param sentinelSubscriptionId string

@description('Object id of the Azure Security Insights service principal (app id 98785600-1bb7-4fb9-b9fa-19afe2c8a360) in this tenant.')
param securityInsightsPrincipalId string

var connectionName = '${baseName}-sentinel-conn'
var workflowName = '${baseName}-triage-playbook'

// Microsoft Sentinel Automation Contributor — the role Sentinel itself needs on
// the playbook's resource group in order to run it.
var automationContributorRoleId = 'f4c81013-99ee-4d62-a7ee-b3f1f648599a'

// The Function's default host key, read at deploy time so the playbook can call
// the function route. Host keys exist as soon as the Function App does, so this
// resolves even before the application code is published.
var functionKey = listKeys('${functionAppResourceId}/host/default', '2022-03-01').functionKeys.default

// --------------------------------------------------------------------------- //
// API connection (managed identity auth)
// --------------------------------------------------------------------------- //

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: connectionName
  location: location
  tags: tags
  kind: 'V1'
  properties: {
    displayName: connectionName
    customParameterValues: {}
    // 'Alternative' selects managed-identity authentication for this connector,
    // which is why no interactive consent step is required after deployment.
    parameterValueType: 'Alternative'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
  }
}

// --------------------------------------------------------------------------- //
// Logic App
// --------------------------------------------------------------------------- //

resource workflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: workflowName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            body: {
              callback_url: '@{listCallbackUrl()}'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Call_triage_function: {
          type: 'Http'
          inputs: {
            method: 'POST'
            uri: 'https://${functionAppName}.azurewebsites.net/api/triage'
            headers: {
              'Content-Type': 'application/json'
              'x-functions-key': functionKey
            }
            body: {
              // Only the ARM id crosses the wire. The Function re-reads the
              // incident from ARM rather than trusting the trigger payload.
              incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
            }
          }
          runAfter: {}
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: connectionName
            id: subscriptionResourceId(
              'Microsoft.Web/locations/managedApis',
              location,
              'azuresentinel'
            )
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
}

// --------------------------------------------------------------------------- //
// Let Sentinel run this playbook
// --------------------------------------------------------------------------- //

resource sentinelCanRunPlaybook 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(securityInsightsPrincipalId)) {
  name: guid(resourceGroup().id, securityInsightsPrincipalId, automationContributorRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      automationContributorRoleId
    )
    principalId: securityInsightsPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// --------------------------------------------------------------------------- //
// Workspace-scoped resources: the Logic App's own access, and the rule itself
// --------------------------------------------------------------------------- //

module workspaceWiring 'automation-rule.bicep' = {
  name: 'triage-automation-rule'
  scope: resourceGroup(sentinelSubscriptionId, sentinelResourceGroup)
  params: {
    workspaceName: sentinelWorkspaceName
    logicAppResourceId: workflow.id
    logicAppPrincipalId: workflow.identity.principalId
    displayName: 'Run the triage agent on new incidents'
  }
}

output logicAppName string = workflow.name
output logicAppResourceId string = workflow.id
output logicAppPrincipalId string = workflow.identity.principalId
output automationRuleId string = workspaceWiring.outputs.automationRuleId
