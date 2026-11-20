targetScope = 'subscription'

@description('Cost profile controlling Defender pricing tier, Policy enforcement mode, and Sentinel rule deployment.')
@allowed([
  'lab'
  'enterprise'
])
param costProfile string = 'lab'

@description('Target Azure cloud profile.')
@allowed([
  'commercial'
  'usgov'
])
param cloudProfile string = 'commercial'

@description('Azure region for subscription-scoped deployment metadata and policy assignment identity.')
param location string = deployment().location

@description('Prefix applied to policy assignment names.')
param namePrefix string = 'avd-sec'

@description('Override Defender for Cloud pricing tier. Defaults to Free in lab and Standard in enterprise.')
@allowed([
  'Free'
  'Standard'
  'Auto'
])
param defenderTierOverride string = 'Auto'

@description('Enable Microsoft Sentinel AVD analytics rules. Defaults to false in lab and true in enterprise when logAnalyticsWorkspaceId is supplied.')
param enableSentinel bool = (costProfile == 'enterprise')

@description('Resource group containing the existing Log Analytics workspace for Sentinel rules.')
param sentinelResourceGroupName string = ''

@description('Resource ID of the existing Log Analytics workspace for Sentinel rules.')
param logAnalyticsWorkspaceId string = ''

var effectiveDefenderTier = defenderTierOverride == 'Free'
  ? 'Free'
  : (defenderTierOverride == 'Standard' ? 'Standard' : (costProfile == 'enterprise' ? 'Standard' : 'Free'))

var effectivePolicyEffect = costProfile == 'enterprise' ? 'Deny' : 'Audit'

module defenderPlans 'modules/defender-plans.bicep' = {
  name: '${namePrefix}-defender-plans'
  params: {
    pricingTier: effectiveDefenderTier
  }
}

module policyAssignments 'modules/policy-assignments.bicep' = {
  name: '${namePrefix}-policy-assignments'
  params: {
    location: location
    namePrefix: namePrefix
    policyEffect: effectivePolicyEffect
  }
}

module sentinelAnalytics 'modules/sentinel-analytics.bicep' = if (enableSentinel && !empty(sentinelResourceGroupName) && !empty(logAnalyticsWorkspaceId)) {
  name: '${namePrefix}-sentinel-analytics'
  scope: resourceGroup(sentinelResourceGroupName)
  params: {
    logAnalyticsWorkspaceId: logAnalyticsWorkspaceId
    namePrefix: namePrefix
  }
}

output costProfile string = costProfile
output cloudProfile string = cloudProfile
output defenderTier string = effectiveDefenderTier
output policyEffect string = effectivePolicyEffect
output sentinelEnabled bool = enableSentinel && !empty(sentinelResourceGroupName) && !empty(logAnalyticsWorkspaceId)
output policyAssignmentIds array = policyAssignments.outputs.assignmentIds
