# B2C generates an RSA signing key.
resource "azureadb2c_trust_framework_key_set" "token_signing" {
  id       = "B2C_1A_TokenSigningKeyContainer"
  use      = "sig"
  key_type = "RSA"
}

# B2C generates an RSA encryption key.
resource "azureadb2c_trust_framework_key_set" "token_encryption" {
  id       = "B2C_1A_TokenEncryptionKeyContainer"
  use      = "enc"
  key_type = "RSA"
}

# Upload a secret without storing it in state (Terraform 1.11+).
# Bump secret_wo_version to upload a new value; that replaces the key set.
variable "facebook_app_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "azureadb2c_trust_framework_key_set" "facebook" {
  id                = "B2C_1A_FacebookSecret"
  use               = "sig"
  key_type          = "oct"
  secret_wo         = var.facebook_app_secret
  secret_wo_version = 1
}

# Upload a secret that is kept in state (any Terraform version).
variable "api_connector_secret" {
  type      = string
  sensitive = true
}

resource "azureadb2c_trust_framework_key_set" "api_connector" {
  id       = "B2C_1A_RestApiKey"
  use      = "enc"
  key_type = "oct"
  secret   = var.api_connector_secret
  expires  = 1893456000 # 2030-01-01T00:00:00Z
}
