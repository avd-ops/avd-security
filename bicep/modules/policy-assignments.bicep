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

// Built-in Azure Policy definitions (tenant-level resources, identical GUIDs in commercial and usgov):
// 1. Key vaults should have soft delete enabled
// 2. Key vaults should have deletion protection enabled (purge protection)
// 3. Storage accounts should have the specified minimum TLS version (TLS1_2)
// 4. Network interfaces should not have public IPs (parameterless built-in; uses DoNotEnforce in Audit/lab mode)
// 5. Virtual Machine should have TrustedLaunch enabled (Audit only; Deny not supported by built-in)
var assignments = [
  {
    name: '${namePrefix}-kv-softdelete'
    displayName: 'AVD Security: Key vaults should have soft delete enabled'
    definitionGuid: '1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d'
    nonComplianceMessage: 'AVD Key Vaults must have soft delete enabled.'
    enforcementMode: 'Default'
    resourceSelectors: []
    parameters: {
      effect: {
        value: policyEffect
      }
    }
  }
  {
    name: '${namePrefix}-kv-purgeprot'
    displayName: 'AVD Security: Key vaults should have deletion protection enabled'
    definitionGuid: '0b60c0b2-2dc2-4e1c-b5c9-abbed971de53'
    nonComplianceMessage: 'AVD Key Vaults must enable purge protection.'
    enforcementMode: 'Default'
    resourceSelectors: []
    parameters: {
      effect: {
        value: policyEffect
      }
    }
  }
  {
    name: '${namePrefix}-st-tls12'
    displayName: 'AVD Security: Storage accounts should have minimum TLS 1.2'
    definitionGuid: 'fe83a0eb-a853-422d-aac2-1bffd182c5d0'
    nonComplianceMessage: 'AVD storage accounts must enforce TLS 1.2 minimum.'
    enforcementMode: 'Default'
    resourceSelectors: []
    parameters: {
      effect: {
        value: policyEffect
      }
      minimumTlsVersion: {
        value: 'TLS1_2'
      }
    }
  }
  {
    name: '${namePrefix}-nic-nopubip'
    displayName: 'AVD Security: Network interfaces should not have public IPs'
    definitionGuid: '83a86a26-fd1f-447c-b59d-e51f44264114'
    nonComplianceMessage: 'Session host network interfaces must not attach public IP addresses.'
    enforcementMode: policyEffect == 'Audit' ? 'DoNotEnforce' : 'Default'
    resourceSelectors: [
      {
        name: 'nicResourceType'
        selectors: [
          {
            kind: 'resourceType'
            in: [
              'Microsoft.Network/networkInterfaces'
            ]
          }
        ]
      }
    ]
    parameters: {}
  }
  {
    name: '${namePrefix}-vm-trustedlaunch'
    displayName: 'AVD Security: Virtual machines should use Trusted Launch'
    definitionGuid: 'c95b54ad-0614-4633-ab29-104b01235cbf'
    nonComplianceMessage: 'AVD session hosts should enable Trusted Launch (Secure Boot + vTPM).'
    enforcementMode: 'Default'
    resourceSelectors: [
      {
        name: 'vmResourceType'
        selectors: [
          {
            kind: 'resourceType'
            in: [
              'Microsoft.Compute/virtualMachines'
            ]
          }
        ]
      }
    ]
    parameters: {
      effect: {
        value: 'Audit'
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
      resourceSelectors: item.resourceSelectors
      nonComplianceMessages: [
        {
          message: item.nonComplianceMessage
        }
      ]
      enforcementMode: item.enforcementMode
    }
  }
]

output assignmentIds array = [for (item, i) in assignments: policyAssignment[i].id]
