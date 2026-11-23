# Import a key set by its container id. The secret is never read back, so
# secret / secret_wo stay unset after the import.
terraform import azureadb2c_trust_framework_key_set.token_signing B2C_1A_TokenSigningKeyContainer
