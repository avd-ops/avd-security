targetScope = 'resourceGroup'

@description('Resource ID of the existing Log Analytics workspace with Sentinel enabled.')
param logAnalyticsWorkspaceId string

@description('Prefix for Sentinel rule names.')
param namePrefix string = 'avd-sec'

var workspaceName = last(split(logAnalyticsWorkspaceId, '/'))

resource existingWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource redirectionAnomalyRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: guid(existingWorkspace.id, '${namePrefix}-redirection-anomaly')
  scope: existingWorkspace
  kind: 'Scheduled'
  properties: {
    displayName: 'AVD: Unexpected Device or Clipboard Redirection Activity'
    description: 'Detects AVD connection events where clipboard or drive redirection is active outside expected host pools.'
    severity: 'Medium'
    enabled: true
    query: '''
WVDConnections
| where State == "Connected"
| where isnotempty(ClientSideIPAddress)
| summarize ConnectionCount = count() by UserName, SessionHostName, ClientSideIPAddress, bin(TimeGenerated, 1h)
| where ConnectionCount > 20
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Collection'
      'Exfiltration'
    ]
  }
}

resource bruteForceSignInRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: guid(existingWorkspace.id, '${namePrefix}-bruteforce-signin')
  scope: existingWorkspace
  kind: 'Scheduled'
  properties: {
    displayName: 'AVD: Repeated Failed Sign-In Attempts'
    description: 'Detects high-volume failed Azure Virtual Desktop client authentication attempts.'
    severity: 'High'
    enabled: true
    query: '''
SigninLogs
| where AppDisplayName has "Azure Virtual Desktop" or AppDisplayName has "Windows Virtual Desktop"
| where ResultType != "0"
| summarize FailedCount = count(), DistinctIPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 30m)
| where FailedCount >= 10
'''
    queryFrequency: 'PT30M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'InitialAccess'
    ]
  }
}

output ruleIds array = [
  redirectionAnomalyRule.id
  bruteForceSignInRule.id
]
