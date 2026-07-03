@description('App Service Plan name')
param name string

@description('Azure region')
param location string

@description('SKU name, e.g. B1, P0v3')
param sku string

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: name
  location: location
  kind: 'linux'
  sku: {
    name: sku
  }
  properties: {
    reserved: true
  }
}

output id string = plan.id
