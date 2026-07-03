targetScope = 'resourceGroup'

@description('Base name used to derive resource names')
param appName string = 'mcpm365'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('App Service Plan SKU')
param appServicePlanSku string = 'B1'

@description('Client ID of the Entra app registration used for admin SSO (see infra/bootstrap/README.md)')
param adminAadClientId string

@description('Tenant ID for the admin SSO Entra app registration')
param adminAadTenantId string = subscription().tenantId

@description('Name of the Entra App Role required for /admin access')
param adminAppRoleName string = 'Admin'

@secure()
@description('Pepper used to HMAC agent client secrets before storing in Table Storage')
param secretPepper string

var storageAccountName = toLower('${appName}st${uniqueString(resourceGroup().id)}')
var webAppName = '${appName}-web'
var appServicePlanName = '${appName}-plan'

module appServicePlan 'modules/appServicePlan.bicep' = {
  name: 'appServicePlan'
  params: {
    name: appServicePlanName
    location: location
    sku: appServicePlanSku
  }
}

module webApp 'modules/webApp.bicep' = {
  name: 'webApp'
  params: {
    name: webAppName
    location: location
    appServicePlanId: appServicePlan.outputs.id
    storageAccountName: storageAccountName
    secretPepper: secretPepper
    adminAppRoleName: adminAppRoleName
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    storageAccountName: storageAccountName
    location: location
    webAppPrincipalId: webApp.outputs.principalId
  }
}

module authSettings 'modules/authSettings.bicep' = {
  name: 'authSettings'
  params: {
    webAppName: webApp.outputs.name
    adminAadClientId: adminAadClientId
    adminAadTenantId: adminAadTenantId
  }
}

output webAppName string = webApp.outputs.name
output webAppHostName string = webApp.outputs.hostName
output webAppPrincipalId string = webApp.outputs.principalId
output storageAccountName string = storage.outputs.name
