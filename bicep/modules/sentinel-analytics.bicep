targetScope = 'resourceGroup'

@description('Resource ID of the existing Log Analytics workspace with Sentinel already onboarded.')
param logAnalyticsWorkspaceId string

@description('Prefix for Sentinel rule names.')
param namePrefix string = 'avd-sec'

var workspaceName = last(split(logAnalyticsWorkspaceId, '/'))
var connectionStormQuery = loadTextContent('../../sentinel/rules/avd-connection-storm.kql')
var bruteForceQuery = loadTextContent('../../sentinel/rules/avd-bruteforce-signin.kql')

resource existingWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource connectionStormRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: guid(existingWorkspace.id, '${namePrefix}-connection-storm')
  scope: existingWorkspace
  kind: 'Scheduled'
  properties: {
    displayName: 'AVD: High-Frequency Session Reconnect Storm'
    description: 'Detects bursts of WVDConnections Connected events per user, host, and client IP. Note: device/clipboard redirection usage requires host EDR telemetry (DeviceEvents/DeviceFileEvents).'
    severity: 'Medium'
    enabled: true
    query: connectionStormQuery
    queryFrequency: 'PT1H'
    queryPeriod: 'PT2H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Impact'
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'UserName'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'SessionHostName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'ClientSideIPAddress'
          }
        ]
      }
    ]
  }
}

resource bruteForceSignInRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: guid(existingWorkspace.id, '${namePrefix}-bruteforce-signin')
  scope: existingWorkspace
  kind: 'Scheduled'
  properties: {
    displayName: 'AVD: Credential Brute-Force or Password Spray'
    description: 'Detects targeted credential failures or password spray against Azure Virtual Desktop and Windows Cloud Login AppIds.'
    severity: 'High'
    enabled: true
    query: bruteForceQuery
    queryFrequency: 'PT30M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'InitialAccess'
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'UserPrincipalName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddress'
          }
        ]
      }
    ]
  }
}

output ruleIds array = [
  connectionStormRule.id
  bruteForceSignInRule.id
]
