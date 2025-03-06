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

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/pflag"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	kubernetesapi "github.com/unikorn-cloud/kubernetes/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
)

var (
	// ErrFormatError is returned when a file doesn't meet the specification.
	ErrFormatError = errors.New("file incorrectly formatted")
)

// Client wraps up interaction with unikorn cloud APIs.
// Exported variables have corresponding flags available, setting them
// in this struct will set the defaults, as different clients will point to
// different servers.
// TODO: listing out each service is quite cumbersome, we should invest some
// effort in a discovery service to streamline this process.
type Client struct {
	// IdentityEndpoint is the identity service endpoint.
	IdentityEndpoint string
	// RegionEndpoint is the region service endpoint.
	RegionEndpoint string
	// KubernetesEndpoint is the kubernetes service endpoint.
	KubernetesEndpoint string
	// TokenFile is an absolute path to the token file.
	TokenFile string
	// CAFile is the non-system dwpublic CA file e.g. Let's Encrypt Staging.
	CAFile string
}

// New creates a new client.
func New() *Client {
	return &Client{}
}

// AddFlags sets default flags and enables the rest to be populated from the CLI.
// This MUST be called after New() essentially.
func (c *Client) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&c.IdentityEndpoint, "identity-endpoint", c.IdentityEndpoint, "The location of the OIDC issuer/discovery and identity services.")
	f.StringVar(&c.RegionEndpoint, "region-endpoint", c.RegionEndpoint, "The location of the region service.")
	f.StringVar(&c.KubernetesEndpoint, "kubernetes-endpoint", c.IdentityEndpoint, "The location of the Kubernetes service.")
	f.StringVar(&c.TokenFile, "token-file", c.TokenFile, "Where to source the access token from.")
	f.StringVar(&c.CAFile, "ca-file", c.CAFile, "CA file for issuer verification.")
}

// loadTokenFile attempts to get a predefined token file from the local file system.
func (c *Client) loadTokenFile() (string, error) {
	data, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// tlsClientConfig either loads the provided TLS CA certificate and returns a new
// TLS config, or returns nil.
func (c *Client) tlsClientConfig() (*tls.Config, error) {
	if c.CAFile == "" {
		//nolint:nilnil
		return nil, nil
	}

	data, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: CA file contains no PEM data", ErrFormatError)
	}

	if block.Type != "CERTIFICATE" && block.Type != "RSA CERTIFICATE" {
		return nil, fmt.Errorf("%e: CA file has wrong PEM type: %s", ErrFormatError, block.Type)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(certificate)

	config := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}

	return config, nil
}

func (c *Client) mutateRequest(ctx context.Context, r *http.Request) error {
	token, err := c.loadTokenFile()
	if err != nil {
		return err
	}

	r.Header.Set("Authorization", "bearer "+token)

	return nil
}

func (c *Client) client(ctx context.Context) (*http.Client, error) {
	// Handle non-system CA certificates.
	tlsClientConfig, err := c.tlsClientConfig()
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
	}

	return client, nil
}

// Identity returns a new identity client.
// NOTE: While we handle race conditions when creating clients, we cannot make the same
// guarantees when actually rotating tokens via the API calls, so treat them as non-reentrant.
func (c *Client) Identity(ctx context.Context) (*identityapi.ClientWithResponses, error) {
	client, err := c.client(ctx)
	if err != nil {
		return nil, err
	}

	identity, err := identityapi.NewClientWithResponses(c.IdentityEndpoint, identityapi.WithHTTPClient(client), identityapi.WithRequestEditorFn(c.mutateRequest))
	if err != nil {
		return nil, err
	}

	return identity, nil
}

// Region returns a new region client.
// NOTE: While we handle race conditions when creating clients, we cannot make the same
// guarantees when actually rotating tokens via the API calls, so treat them as non-reentrant.
func (c *Client) Region(ctx context.Context) (*regionapi.ClientWithResponses, error) {
	client, err := c.client(ctx)
	if err != nil {
		return nil, err
	}

	region, err := regionapi.NewClientWithResponses(c.RegionEndpoint, regionapi.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	return region, nil
}

// Kubernetes returns a new kubernetes client.
// NOTE: While we handle race conditions when creating clients, we cannot make the same
// guarantees when actually rotating tokens via the API calls, so treat them as non-reentrant.
func (c *Client) Kubernetes(ctx context.Context) (*kubernetesapi.ClientWithResponses, error) {
	client, err := c.client(ctx)
	if err != nil {
		return nil, err
	}

	kubernetes, err := kubernetesapi.NewClientWithResponses(c.KubernetesEndpoint, kubernetesapi.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	return kubernetes, nil
}
