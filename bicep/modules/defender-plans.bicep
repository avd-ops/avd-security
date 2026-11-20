targetScope = 'subscription'

@description('Microsoft Defender for Cloud pricing tier for AVD-relevant resource types.')
@allowed([
  'Free'
  'Standard'
])
param pricingTier string = 'Free'

var resourceTypes = [
  'VirtualMachines'
  'KeyVaults'
  'StorageAccounts'
]

resource defenderPricing 'Microsoft.Security/pricings@2024-01-01' = [
  for resourceType in resourceTypes: {
    name: resourceType
    properties: {
      pricingTier: pricingTier
    }
  }
]

output configuredPlans array = resourceTypes
output pricingTier string = pricingTier
