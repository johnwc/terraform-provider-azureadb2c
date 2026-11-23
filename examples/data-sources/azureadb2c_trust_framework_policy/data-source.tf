data "azureadb2c_trust_framework_policy" "base" {
  id = "B2C_1A_TrustFrameworkBase"
}

output "base_policy_tenant" {
  value = data.azureadb2c_trust_framework_policy.base.tenant_id
}
