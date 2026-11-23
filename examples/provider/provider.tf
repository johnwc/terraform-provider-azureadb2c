terraform {
  required_providers {
    azureadb2c = { source = "johnwc/azureadb2c" }
  }
}

# Auth resolves ARM_* / AZURE_* env vars (secret, certificate, OIDC, MSI, CLI).
# App-only needs the Microsoft Graph application permissions
# Policy.ReadWrite.TrustFramework and TrustFrameworkKeySet.ReadWrite.All.
provider "azureadb2c" {
  tenant_id = "contoso.onmicrosoft.com"
  client_id = "00000000-0000-0000-0000-000000000000"
  # client_secret = var.client_secret   # or ARM_CLIENT_SECRET
}
