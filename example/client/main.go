/*
Copyright 2024-2025 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/client-go/pkg/client"
)

func main() {
	ctx := context.Background()

	tokenSource := client.NewFileTokenSource()
	tokenSource.TokenFile = filepath.Join(os.Getenv("HOME"), ".config/unikorn/token")

	// Initialize the client with some default values.
	// This allows you to tailor to your specific environment and
	// brand if you aren't a fan of unicorns.  Shame on you.
	client := client.New(tokenSource)
	client.IdentityEndpoint = "https://identity.spjmurray.co.uk"
	client.RegionEndpoint = "https://region.spjmurray.co.uk"
	client.ComputeEndpoint = "https://compute.spjmurray.co.uk"
	client.KubernetesEndpoint = "https://kubernetes.spjmurray.co.uk"

	client.AddFlags(pflag.CommandLine)

	pflag.Parse()

	// Do some work.  Be careful with API calls, they aren't reentrant by default
	// so you may risk races with concurrent token refresh unless the APIs are
	// decorated with middleware of some variety.
	// TODO: that ^^.
	identity, err := client.Identity(ctx)
	if err != nil {
		fmt.Println("FATAL: unable to initialize client:", err)
		os.Exit(1)
	}

	response, err := identity.GetApiV1OrganizationsWithResponse(ctx, nil)
	if err != nil {
		fmt.Println("FATAL: unable to read organizations:", err)
		os.Exit(1)
	}

	if response.StatusCode() != http.StatusOK {
		fmt.Println("FATAL: unexpected status code:", response.HTTPResponse.StatusCode)
		os.Exit(1)
	}

	for _, organization := range *response.JSON200 {
		fmt.Println(organization.Metadata.Name)
	}
}
