// terraform-provider-azureadb2c is a Terraform/OpenTofu provider for Azure AD
// B2C custom policy configuration (Identity Experience Framework), managed
// through the Microsoft Graph trustFramework API.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/johnwc/terraform-provider-azureadb2c/internal/provider"
)

// version is set by goreleaser at build time.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/johnwc/azureadb2c",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
