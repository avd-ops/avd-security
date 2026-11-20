targetScope = 'subscription'

@description('Microsoft Defender for Cloud pricing tier for AVD-relevant resource types.')
@allowed([
  'Free'
  'Standard'
])
param pricingTier string = 'Free'

@description('Enable Defender for Storage On-Upload Malware Scanning (per-GB cost).')
param enableStorageMalwareScanning bool = false

resource defenderVm 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'VirtualMachines'
  properties: pricingTier == 'Standard'
    ? {
        pricingTier: 'Standard'
        subPlan: 'P1'
      }
    : {
        pricingTier: 'Free'
      }
}

resource defenderKeyVault 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'KeyVaults'
  properties: {
    pricingTier: pricingTier
  }
}

resource defenderStorage 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'StorageAccounts'
  properties: pricingTier == 'Standard'
    ? {
        pricingTier: 'Standard'
        subPlan: 'DefenderForStorageV2'
        extensions: [
          {
            name: 'OnUploadMalwareScanning'
            isEnabled: enableStorageMalwareScanning ? 'True' : 'False'
          }
          {
            name: 'SensitiveDataDiscovery'
            isEnabled: 'False'
          }
        ]
      }
    : {
        pricingTier: 'Free'
      }
}

output configuredPlans array = [
  defenderVm.name
  defenderKeyVault.name
  defenderStorage.name
]
output pricingTier string = pricingTier
