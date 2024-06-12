/*
Copyright 2024 the Unikorn Authors.

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	kubernetesapi "github.com/unikorn-cloud/unikorn/pkg/openapi"
)

const (
	// redirectURL is made up, we cannot redirect from the CLI!
	redirectURL = "https://identity-client.unikorn-cloud.org/oauth2/callback"
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
	// tokenSource caches the token source so we can save a refreshed token
	// for the next invocation.
	tokenSource oauth2.TokenSource
	// lock for the tokenSource.
	lock sync.Mutex
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
func (c *Client) loadTokenFile() (*oauth2.Token, error) {
	data, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{}

	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	// IANA only specifies "expires_in", and that's relative to the authentication
	// call, not useful at all for offline use, so we force the refresh of the token
	// when a new token is detected.
	// See: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml)
	if token.Expiry.IsZero() {
		token.Expiry = time.Now()
	}

	return token, nil
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

// setupTokenSource create and cache the token source, so we only have one version
// to worry about when extracting tokens.
func (c *Client) setupTokenSource(ctx context.Context, tlsClientConfig *tls.Config) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.tokenSource != nil {
		return nil
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	ctx = oidc.ClientContext(ctx, client)

	// Perform OIDC service discovery and configure oauth2.
	provider, err := oidc.NewProvider(ctx, c.IdentityEndpoint)
	if err != nil {
		return err
	}

	config := &oauth2.Config{
		Endpoint:    provider.Endpoint(),
		RedirectURL: redirectURL,
	}

	// Pre-populate the oauth2 token from our local file.
	token, err := c.loadTokenFile()
	if err != nil {
		return err
	}

	c.tokenSource = config.TokenSource(ctx, token)

	return nil
}

// client returns a new http client that will transparently do oauth2 header
// injection and refresh token updates.
func (c *Client) client(ctx context.Context) (*http.Client, error) {
	// Handle non-system CA certificates for the OIDC discovery protocol
	// and oauth2 token refresh. This will return nil if none is specified
	// and default to the system roots.
	tlsClientConfig, err := c.tlsClientConfig()
	if err != nil {
		return nil, err
	}

	if err := c.setupTokenSource(ctx, tlsClientConfig); err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &oauth2.Transport{
			Source: c.tokenSource,
			Base: &http.Transport{
				TLSClientConfig: tlsClientConfig,
			},
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

	identity, err := identityapi.NewClientWithResponses(c.IdentityEndpoint, identityapi.WithHTTPClient(client))
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

// Shutdown must be called at least once to flush rotated keys to disk.
func (c *Client) Shutdown() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.tokenSource == nil {
		return nil
	}

	token, err := c.tokenSource.Token()
	if err != nil {
		return err
	}

	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	if err := os.WriteFile(c.TokenFile, data, 0600); err != nil {
		return err
	}

	c.tokenSource = nil

	return nil
}
