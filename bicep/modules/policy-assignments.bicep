targetScope = 'subscription'

@description('Location metadata for policy assignment.')
param location string

@description('Prefix for policy assignment names.')
param namePrefix string = 'avd-sec'

@description('Policy effect applied to AVD security baseline assignments.')
@allowed([
  'Audit'
  'Deny'
])
param policyEffect string = 'Audit'

@description('Optional scopes excluded from policy enforcement.')
param notScopes array = []

// Built-in Azure Policy definitions (tenant-level resources):
// 1. Key vaults should have soft delete enabled
// 2. Secure transfer to storage accounts should be enabled
// 3. Network interfaces should not have public IPs
var assignments = [
  {
    name: '${namePrefix}-kv-softdelete'
    displayName: 'AVD Security: Key vaults should have soft delete enabled'
    definitionGuid: '1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d'
    nonComplianceMessage: 'AVD Key Vaults must have soft delete enabled.'
    parameters: {
      effect: {
        value: policyEffect
      }
    }
  }
  {
    name: '${namePrefix}-st-https'
    displayName: 'AVD Security: Secure transfer to storage accounts should be enabled'
    definitionGuid: '404c3081-a854-4457-ae30-26a93ef943f9'
    nonComplianceMessage: 'AVD storage accounts must require secure transfer (HTTPS).'
    parameters: {
      effect: {
        value: policyEffect
      }
    }
  }
  {
    name: '${namePrefix}-nic-nopubip'
    displayName: 'AVD Security: Network interfaces should not have public IPs'
    definitionGuid: '83a86a26-fd1f-447c-b59d-e51f44264114'
    nonComplianceMessage: 'Session host network interfaces must not attach public IP addresses.'
    parameters: {
      effect: {
        value: policyEffect
      }
    }
  }
]

resource policyAssignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = [
  for item in assignments: {
    name: item.name
    location: location
    properties: {
      displayName: item.displayName
      policyDefinitionId: tenantResourceId('Microsoft.Authorization/policyDefinitions', item.definitionGuid)
      parameters: item.parameters
      notScopes: notScopes
      nonComplianceMessages: [
        {
          message: item.nonComplianceMessage
        }
      ]
      enforcementMode: 'Default'
    }
  }
]

output assignmentIds array = [for (item, i) in assignments: policyAssignment[i].id]
