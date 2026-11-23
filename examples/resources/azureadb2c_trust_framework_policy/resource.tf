variable "tenant_domain" {
  type    = string
  default = "contoso.onmicrosoft.com"
}

# Policy keys referenced by the base policy.
resource "azureadb2c_trust_framework_key_set" "token_signing" {
  id       = "B2C_1A_TokenSigningKeyContainer"
  use      = "sig"
  key_type = "RSA"
}

resource "azureadb2c_trust_framework_key_set" "token_encryption" {
  id       = "B2C_1A_TokenEncryptionKeyContainer"
  use      = "enc"
  key_type = "RSA"
}

# Each child policy receives its parent's .id through templatefile(), so
# Terraform uploads base -> extensions -> relying party in order (and deletes
# them in reverse). The base policy receives the key set ids the same way.
resource "azureadb2c_trust_framework_policy" "base" {
  policy = templatefile("${path.module}/policies/base.xml.tftpl", {
    tenant                   = var.tenant_domain
    policy_id                = "B2C_1A_TrustFrameworkBase"
    signing_key_container    = azureadb2c_trust_framework_key_set.token_signing.id
    encryption_key_container = azureadb2c_trust_framework_key_set.token_encryption.id
  })
}

resource "azureadb2c_trust_framework_policy" "extensions" {
  policy = templatefile("${path.module}/policies/extensions.xml.tftpl", {
    tenant         = var.tenant_domain
    policy_id      = "B2C_1A_TrustFrameworkExtensions"
    base_policy_id = azureadb2c_trust_framework_policy.base.id
  })
}

resource "azureadb2c_trust_framework_policy" "signup_signin" {
  policy = templatefile("${path.module}/policies/signup_signin.xml.tftpl", {
    tenant         = var.tenant_domain
    policy_id      = "B2C_1A_SignUpOrSignIn"
    base_policy_id = azureadb2c_trust_framework_policy.extensions.id
  })
}
