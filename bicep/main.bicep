targetScope = 'subscription'

@description('Cost profile controlling Defender pricing tier and Policy enforcement mode.')
@allowed([
  'lab'
  'enterprise'
])
param costProfile string = 'lab'

@description('Target Azure cloud profile. Currently commercial only; usgov policy parity is pending C19 verification.')
@allowed([
  'commercial'
])
param cloudProfile string = 'commercial'

@description('Azure region for subscription-scoped deployment metadata and policy assignment identity.')
param location string = deployment().location

@description('Prefix applied to policy assignment and rule names (lowercase alphanumeric and hyphens, 3-16 chars).')
@minLength(3)
@maxLength(16)
param namePrefix string = 'avd-sec'

@description('Defender for Cloud pricing override. In lab, Auto leaves existing subscription plans untouched (read-only); Free explicitly sets Free; Standard is only permitted when costProfile is enterprise.')
@allowed([
  'Auto'
  'Free'
  'Standard'
])
param defenderTierOverride string = 'Auto'

@description('Enable Defender for Storage On-Upload Malware Scanning (incurs per-GB scan cost). Off by default.')
param enableStorageMalwareScanning bool = false

@description('Resource IDs or scopes excluded from Deny policy assignments.')
param policyNotScopes array = []

@description('Deploy Microsoft Sentinel AVD analytics rules onto an existing Sentinel-onboarded Log Analytics workspace.')
param enableSentinel bool = false

@description('Resource ID of the existing Sentinel-onboarded Log Analytics workspace.')
param logAnalyticsWorkspaceId string = ''

// In lab, Auto never writes to Microsoft.Security/pricings (avoids downgrading existing paid plans).
// Standard is never allowed in lab; only enterprise (or explicit Free) writes Defender plans.
var deployDefenderPlans = costProfile == 'enterprise'
  ? true
  : (defenderTierOverride == 'Free')

var effectiveDefenderTier = costProfile == 'enterprise'
  ? (defenderTierOverride == 'Free' ? 'Free' : 'Standard')
  : 'Free'

var effectivePolicyEffect = costProfile == 'enterprise' ? 'Deny' : 'Audit'

var sentinelResourceGroupName = (!empty(logAnalyticsWorkspaceId) && length(split(logAnalyticsWorkspaceId, '/')) >= 5)
  ? split(logAnalyticsWorkspaceId, '/')[4]
  : ''
var sentinelCanDeploy = enableSentinel && !empty(sentinelResourceGroupName) && !empty(logAnalyticsWorkspaceId)

module defenderPlans 'modules/defender-plans.bicep' = if (deployDefenderPlans) {
  name: '${namePrefix}-defender-plans'
  params: {
    pricingTier: effectiveDefenderTier
    enableStorageMalwareScanning: enableStorageMalwareScanning
  }
}

module policyAssignments 'modules/policy-assignments.bicep' = {
  name: '${namePrefix}-policy-assignments'
  params: {
    location: location
    namePrefix: namePrefix
    policyEffect: effectivePolicyEffect
    notScopes: policyNotScopes
  }
}

module sentinelAnalytics 'modules/sentinel-analytics.bicep' = if (sentinelCanDeploy) {
  name: '${namePrefix}-sentinel-analytics'
  scope: resourceGroup(sentinelResourceGroupName)
  params: {
    logAnalyticsWorkspaceId: logAnalyticsWorkspaceId
    namePrefix: namePrefix
  }
}

output costProfile string = costProfile
output cloudProfile string = cloudProfile
output defenderPlansDeployed bool = deployDefenderPlans
output defenderTier string = deployDefenderPlans ? effectiveDefenderTier : 'Unchanged'
output policyEffect string = effectivePolicyEffect
output sentinelEnabled bool = sentinelCanDeploy
output policyAssignmentIds array = policyAssignments.outputs.assignmentIds
