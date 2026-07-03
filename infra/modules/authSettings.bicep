@description('Name of the Web App to configure Easy Auth on')
param webAppName string

@description('Client ID of the Entra app registration used for admin SSO (see infra/bootstrap/README.md)')
param adminAadClientId string

@description('Tenant ID for the admin SSO Entra app registration')
param adminAadTenantId string

// Easy Auth is site-wide -- it cannot be scoped to only /admin/*. We set
// unauthenticatedClientAction to AllowAnonymous so /mcp/* is never redirected
// to a login page, and enforce the admin check in application code
// (webapp/admin_routes.py) by reading the platform-injected
// X-MS-CLIENT-PRINCIPAL header, which callers cannot forge directly.
resource webApp 'Microsoft.Web/sites@2023-12-01' existing = {
  name: webAppName
}

resource authSettingsV2 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: webApp
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
    }
    globalValidation: {
      requireAuthentication: false
      unauthenticatedClientAction: 'AllowAnonymous'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: adminAadClientId
          openIdIssuer: 'https://login.microsoftonline.com/${adminAadTenantId}/v2.0'
        }
        validation: {
          // A plain OIDC sign-in's ID token has `aud` == the app's client ID,
          // not an App ID URI (api://...) -- that form only applies to access
          // tokens for a scope Easy Auth isn't requesting here. Using
          // api://<clientId> caused every login to be rejected with a 401
          // after an otherwise-successful Entra sign-in.
          allowedAudiences: [
            adminAadClientId
          ]
        }
      }
    }
  }
}
