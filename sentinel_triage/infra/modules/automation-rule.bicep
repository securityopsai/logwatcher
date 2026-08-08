// Workspace-scoped half of the playbook wiring: the automation rule that fires
// on new incidents, plus the Logic App identity's own access to the workspace
// (the Sentinel connector's trigger reads incidents as the Logic App).

targetScope = 'resourceGroup'

param workspaceName string

@description('Resource id of the playbook to run.')
param logicAppResourceId string

@description('Principal id of the managed identity belonging to the playbook.')
param logicAppPrincipalId string

param displayName string = 'Run the triage agent on new incidents'

@description('Rule order. Lower numbers run first; 1000 leaves room for existing rules.')
param order int = 1000

var sentinelResponderRoleId = '3e150937-b8fe-4cfb-8069-0eaf05ecd056'

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource logicAppResponder 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: workspace
  name: guid(workspace.id, logicAppPrincipalId, sentinelResponderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      sentinelResponderRoleId
    )
    principalId: logicAppPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Automation rule names must be GUIDs. Deriving one from the workspace keeps
// redeployments idempotent instead of piling up duplicate rules.
resource automationRule 'Microsoft.SecurityInsights/automationRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'sentinel-triage-agent')
  properties: {
    displayName: displayName
    order: order
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: []
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: logicAppResourceId
          tenantId: subscription().tenantId
        }
      }
    ]
  }
}

output automationRuleId string = automationRule.id
