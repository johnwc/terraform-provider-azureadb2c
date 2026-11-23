data "azureadb2c_trust_framework_key_set" "token_signing" {
  id = "B2C_1A_TokenSigningKeyContainer"
}

output "token_signing_key_id" {
  value = data.azureadb2c_trust_framework_key_set.token_signing.key_id
}
