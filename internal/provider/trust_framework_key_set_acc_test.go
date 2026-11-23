package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// testAccName returns a throwaway B2C_1A_TfAcc<random> name.
func testAccName() string {
	return "B2C_1A_TfAcc" + strings.ToLower(acctest.RandStringFromCharSet(10, acctest.CharSetAlpha))
}

// TestAccTrustFrameworkKeySet_generateRSA generates an RSA signing key, reads it
// with the data source, imports it by id and destroys it. Run with TF_ACC=1 and
// ARM_* credentials pointing at a disposable dev B2C tenant.
func TestAccTrustFrameworkKeySet_generateRSA(t *testing.T) {
	name := testAccName()
	const rn = "azureadb2c_trust_framework_key_set.test"
	const dn = "data.azureadb2c_trust_framework_key_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDestroy,
		Steps: []resource.TestStep{
			{ // create
				Config: testAccKeySetGenerateConfig(name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rn, "id", name),
					resource.TestCheckResourceAttr(rn, "use", "sig"),
					resource.TestCheckResourceAttr(rn, "key_type", "RSA"),
					resource.TestCheckResourceAttrSet(rn, "key_id"),
					resource.TestCheckNoResourceAttr(rn, "secret"),
					resource.TestCheckResourceAttr(dn, "use", "sig"),
					resource.TestCheckResourceAttr(dn, "key_type", "RSA"),
					resource.TestCheckResourceAttrPair(dn, "key_id", rn, "key_id"),
				),
			},
			{ // import by id
				ResourceName:      rn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccTrustFrameworkKeySet_uploadSecret uploads an oct encryption secret,
// imports it (the secret is not read back) and destroys it.
func TestAccTrustFrameworkKeySet_uploadSecret(t *testing.T) {
	name := testAccName()
	secret := acctest.RandStringFromCharSet(40, acctest.CharSetAlpha)
	const rn = "azureadb2c_trust_framework_key_set.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDestroy,
		Steps: []resource.TestStep{
			{ // create
				Config: testAccKeySetUploadConfig(name, secret),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rn, "id", name),
					resource.TestCheckResourceAttr(rn, "use", "enc"),
					resource.TestCheckResourceAttr(rn, "key_type", "oct"),
					resource.TestCheckResourceAttrSet(rn, "key_id"),
				),
			},
			{ // import by id
				ResourceName:            rn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"secret"},
			},
		},
	})
}

// TestAccTrustFrameworkKeySet_writeOnlySecret uploads an oct secret through the
// write-only secret_wo (Terraform 1.11 or later), checks it is not kept in
// state, and bumps secret_wo_version to replace the key set.
func TestAccTrustFrameworkKeySet_writeOnlySecret(t *testing.T) {
	name := testAccName()
	secret := acctest.RandStringFromCharSet(40, acctest.CharSetAlpha)
	rotated := acctest.RandStringFromCharSet(40, acctest.CharSetAlpha)
	const rn = "azureadb2c_trust_framework_key_set.test"
	keyIDDiffers := statecheck.CompareValue(compare.ValuesDiffer())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		CheckDestroy:             testAccCheckDestroy,
		Steps: []resource.TestStep{
			{ // create
				Config: testAccKeySetWriteOnlyConfig(name, secret, 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rn, "id", name),
					resource.TestCheckResourceAttr(rn, "key_type", "oct"),
					resource.TestCheckResourceAttr(rn, "secret_wo_version", "1"),
					resource.TestCheckResourceAttrSet(rn, "key_id"),
					resource.TestCheckNoResourceAttr(rn, "secret_wo"),
					resource.TestCheckNoResourceAttr(rn, "secret"),
				),
				ConfigStateChecks: []statecheck.StateCheck{keyIDDiffers.AddStateValue(rn, tfjsonpath.New("key_id"))},
			},
			{ // a new version replaces the key set with the rotated secret
				Config: testAccKeySetWriteOnlyConfig(name, rotated, 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(rn, plancheck.ResourceActionReplace)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rn, "secret_wo_version", "2"),
					resource.TestCheckResourceAttrSet(rn, "key_id"),
					resource.TestCheckNoResourceAttr(rn, "secret_wo"),
				),
				ConfigStateChecks: []statecheck.StateCheck{keyIDDiffers.AddStateValue(rn, tfjsonpath.New("key_id"))},
			},
		},
	})
}

func testAccKeySetWriteOnlyConfig(name, secret string, version int) string {
	return fmt.Sprintf(`
resource "azureadb2c_trust_framework_key_set" "test" {
  id                = %[1]q
  use               = "enc"
  key_type          = "oct"
  secret_wo         = %[2]q
  secret_wo_version = %[3]d
}
`, name, secret, version)
}

func testAccKeySetGenerateConfig(name string) string {
	return fmt.Sprintf(`
resource "azureadb2c_trust_framework_key_set" "test" {
  id       = %[1]q
  use      = "sig"
  key_type = "RSA"
}

data "azureadb2c_trust_framework_key_set" "test" {
  id = azureadb2c_trust_framework_key_set.test.id
}
`, name)
}

func testAccKeySetUploadConfig(name, secret string) string {
	return fmt.Sprintf(`
resource "azureadb2c_trust_framework_key_set" "test" {
  id       = %[1]q
  use      = "enc"
  key_type = "oct"
  secret   = %[2]q
}
`, name, secret)
}
