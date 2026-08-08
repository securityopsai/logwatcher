// Secret storage for the Anthropic API key.
//
// Deployed only when llmProvider is 'anthropic'. Kept in its own module so the
// caller can make the whole thing conditional without ever dereferencing a
// resource that may not exist — the caller composes the secret URI from names
// rather than reading it back.

targetScope = 'resourceGroup'

@description('Name of the vault. Must be globally unique, 3-24 chars, and must not end with a hyphen.')
param keyVaultName string

param location string
param tags object = {}

@description('Name of the secret to store.')
param secretName string

@description('The secret value.')
@secure()
param secretValue string

@description('Principal granted read access to the secret (the Function App identity).')
param readerPrincipalId string

// Key Vault Secrets User — read secret values, nothing else. This is what lets
// the Function App resolve its @Microsoft.KeyVault(...) app setting.
var secretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    // RBAC rather than access policies, so the role assignment below is the
    // single place access is granted.
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

resource secret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: secretName
  properties: {
    value: secretValue
  }
}

resource secretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, readerPrincipalId, secretsUserRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      secretsUserRoleId
    )
    principalId: readerPrincipalId
    principalType: 'ServicePrincipal'
  }
}

output vaultName string = vault.name
output vaultUri string = vault.properties.vaultUri
// Versionless URI: app settings resolve the current version on each restart.
output secretUri string = '${vault.properties.vaultUri}secrets/${secretName}/'
