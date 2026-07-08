@description('Web App name')
param name string

@description('Azure region')
param location string

@description('Resource ID of the App Service Plan')
param appServicePlanId string

@description('Name of the storage account used for the ClientSecrets table')
param storageAccountName string

@secure()
@description('Pepper used to HMAC agent client secrets before storing in Table Storage')
param secretPepper string

@description('Name of the Entra App Role required for /admin access')
param adminAppRoleName string

@secure()
@description('Client secret for the admin SSO app registration -- Easy Auth v2 needs this to exchange the auth code for a token at /.auth/login/aad/callback (confidential client flow)')
param adminAadClientSecret string

resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: name
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlanId
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      appCommandLine: 'gunicorn -k uvicorn.workers.UvicornWorker -w 1 --timeout 600 --forwarded-allow-ips="*" -b 0.0.0.0:8000 webapp.asgi:app'
      appSettings: [
        {
          name: 'AUTH_MODE'
          value: 'managed_identity'
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
        {
          name: 'STORAGE_ACCOUNT_NAME'
          value: storageAccountName
        }
        {
          name: 'SECRET_PEPPER'
          value: secretPepper
        }
        {
          name: 'ADMIN_APP_ROLE_NAME'
          value: adminAppRoleName
        }
        {
          name: 'WEBSITES_PORT'
          value: '8000'
        }
        {
          // Conventional app setting name Easy Auth v2 expects for
          // registration.clientSecretSettingName (see authSettings.bicep).
          name: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
          value: adminAadClientSecret
        }
      ]
    }
  }
}

output name string = webApp.name
output principalId string = webApp.identity.principalId
output hostName string = webApp.properties.defaultHostName
