targetScope = 'resourceGroup'

@description('Resource ID of the existing Log Analytics workspace with Sentinel already onboarded.')
param logAnalyticsWorkspaceId string

@description('Prefix for Sentinel rule names.')
param namePrefix string = 'avd-sec'

var workspaceName = last(split(logAnalyticsWorkspaceId, '/'))
var connectionStormQuery = loadTextContent('../../sentinel/rules/avd-connection-storm.kql')
var bruteForceQuery = loadTextContent('../../sentinel/rules/avd-bruteforce-signin.kql')
var tsclientExfilQuery = loadTextContent('../../sentinel/rules/avd-tsclient-exfiltration.kql')
var localAdminChangeQuery = loadTextContent('../../sentinel/rules/avd-local-admin-change.kql')

resource existingWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource connectionStormRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: guid(existingWorkspace.id, '${namePrefix}-connection-storm')
  scope: existingWorkspace
  kind: 'Scheduled'
  properties: {
    displayName: 'AVD: High-Frequency Session Reconnect Storm'
    description: 'Detects bursts of WVDConnections Connected events per user, host, and client IP.'
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

resource tsclientExfilRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: guid(existingWorkspace.id, '${namePrefix}-tsclient-exfil')
  scope: existingWorkspace
  kind: 'Scheduled'
  properties: {
    displayName: 'AVD: RDP Drive Redirection (\\\\tsclient) File Activity'
    description: 'Detects host EDR file or process events targeting \\\\tsclient\\ redirected client drives on AVD session hosts.'
    severity: 'Medium'
    enabled: true
    query: tsclientExfilQuery
    queryFrequency: 'PT1H'
    queryPeriod: 'PT2H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Exfiltration'
      'Collection'
    ]
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'DeviceName'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AccountName'
          }
        ]
      }
    ]
  }
}

resource localAdminChangeRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: guid(existingWorkspace.id, '${namePrefix}-local-admin-change')
  scope: existingWorkspace
  kind: 'Scheduled'
  properties: {
    displayName: 'AVD: Local Administrators Group Modification'
    description: 'Detects unexpected additions to the local Administrators group on AVD session hosts (SecurityEvent 4732).'
    severity: 'High'
    enabled: true
    query: localAdminChangeQuery
    queryFrequency: 'PT30M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Persistence'
      'PrivilegeEscalation'
    ]
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'Computer'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'SubjectUserName'
          }
        ]
      }
    ]
  }
}

output ruleIds array = [
  connectionStormRule.id
  bruteForceSignInRule.id
  tsclientExfilRule.id
  localAdminChangeRule.id
]
