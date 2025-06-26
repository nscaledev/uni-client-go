/*
Copyright 2025 the Unikorn Authors.

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

package tokenrotator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/client-go/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrMissingSecretKey = errors.New("secret key is missing from data")
	ErrUnexpectedStatus = errors.New("unexpected status code")
	ErrConsistency      = errors.New("consistency error")
)

// TokenRotator encapsulates the idea of polling a service account access token
// that is stored in a secret (and presumably mounted in other Pods for services
// to consume).  It will rotate and update the secret when instructed to as defined
// by a threshold.
type TokenRotator struct {
	// Namespace we are running in.
	Namespace string
	// SecretName is the name of the token secret.
	SecretName string
	// SecretTokenKey is the name of the key in the secret the token is stored in.
	SecretTokenKey string
	// TokenExpiryThreshold is how long before expiry to attempt token rotation.
	TokenExpiryThreshold time.Duration
	// TokenPollingDuration is how long to wait before polling the token's expiry.
	// This is deliberate, rather than relying on caching as someone may have done
	// something outside of our control, and we'd like to know about it.
	TokenPollingDuration time.Duration
	// secret is the cached secret used for updates.
	secret corev1.Secret
	// tokenSource is used to store the access token.
	tokenSource *client.VariableTokenSource
	// client is the Unikorn client.
	client *client.Client
}

func New() *TokenRotator {
	tokenSource := client.NewVariableTokenSource("")
	client := client.New(tokenSource)

	return &TokenRotator{
		tokenSource: tokenSource,
		client:      client,
	}
}

func (r *TokenRotator) AddFlags(f *pflag.FlagSet) {
	r.client.AddFlags(f)

	f.StringVar(&r.Namespace, "namespace", "", "Namespace the token secret is located in")
	f.StringVar(&r.SecretName, "secret-name", "service-token", "Secret containing the token")
	f.StringVar(&r.SecretTokenKey, "secret-token-key", "token", "Key in the secret underwhich the token is located")
	f.DurationVar(&r.TokenExpiryThreshold, "token-expiry-threshold", 30*24*time.Hour, "How long before token expiry to begin rotation attempts.")
	f.DurationVar(&r.TokenPollingDuration, "token-polling-duration", time.Hour, "How long to wait before checking the token expiry")
}

// loadToken reads the token from the secret and injects it into the token source for use
// against the Identity API.
func (r *TokenRotator) loadToken(ctx context.Context, cli crclient.Client) error {
	if err := cli.Get(ctx, crclient.ObjectKey{Name: r.SecretName}, &r.secret); err != nil {
		return err
	}

	token, ok := r.secret.Data[r.SecretTokenKey]
	if !ok {
		return ErrMissingSecretKey
	}

	r.tokenSource.Update(string(token))

	return nil
}

// serviceAccountInfo records service account token introspection information.
type serviceAccountInfo struct {
	// organizationID the service account token belongs to.
	organizationID string
	// serviceAccountID the service account token belongs to.
	serviceAccountID string
	// expiry when the service account token is due to expire.
	expiry time.Time
}

// getOrganization gets the service account token's organization.
func (r *TokenRotator) getOrganization(ctx context.Context, identity *identityapi.ClientWithResponses) (*identityapi.OrganizationRead, error) {
	response, err := identity.GetApiV1OrganizationsWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("%w: wanted %v, got %v", ErrUnexpectedStatus, http.StatusOK, response.HTTPResponse.StatusCode)
	}

	results := *response.JSON200

	if len(results) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one organization, got %v", ErrConsistency, len(results))
	}

	return &results[0], nil
}

// getServiceAccount gets the service account token's service account.
func (r *TokenRotator) getServiceAccount(ctx context.Context, identity *identityapi.ClientWithResponses, organization *identityapi.OrganizationRead) (*identityapi.ServiceAccountRead, error) {
	response, err := identity.GetApiV1OrganizationsOrganizationIDServiceaccountsWithResponse(ctx, organization.Metadata.Id)
	if err != nil {
		return nil, err
	}

	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("%w: wanted %v, got %v", ErrUnexpectedStatus, http.StatusOK, response.HTTPResponse.StatusCode)
	}

	results := *response.JSON200

	// TODO: we can filter by name here if the service account has privileges that
	// allow it to see more than one.
	if len(results) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one service account, got %v", ErrConsistency, len(results))
	}

	return &results[0], nil
}

// introspectToken looks up the token's organization and service account IDs, recoding
// the time of expiry.
func (r *TokenRotator) introspectToken(ctx context.Context) (*serviceAccountInfo, error) {
	identity, err := r.client.Identity(ctx)
	if err != nil {
		return nil, err
	}

	organization, err := r.getOrganization(ctx, identity)
	if err != nil {
		return nil, err
	}

	serviceAccount, err := r.getServiceAccount(ctx, identity, organization)
	if err != nil {
		return nil, err
	}

	result := &serviceAccountInfo{
		organizationID:   organization.Metadata.Id,
		serviceAccountID: serviceAccount.Metadata.Id,
		expiry:           serviceAccount.Status.Expiry,
	}

	return result, nil
}

// rotateToken does the token rotation and stores the new token back into the secret.
func (r *TokenRotator) rotateToken(ctx context.Context, cli crclient.Client, info *serviceAccountInfo) error {
	identity, err := r.client.Identity(ctx)
	if err != nil {
		return err
	}

	response, err := identity.PostApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountIDRotateWithResponse(ctx, info.organizationID, info.serviceAccountID)
	if err != nil {
		return err
	}

	if response.StatusCode() != http.StatusOK {
		return fmt.Errorf("%w: wanted %v, got %v", ErrUnexpectedStatus, http.StatusOK, response.HTTPResponse.StatusCode)
	}

	result := *response.JSON200

	if result.Status.AccessToken == nil {
		return fmt.Errorf("%w: token rotation request doesn't contain the new token", ErrConsistency)
	}

	r.secret.Data[r.SecretTokenKey] = []byte(*result.Status.AccessToken)

	if err := cli.Update(ctx, &r.secret); err != nil {
		return err
	}

	return nil
}

// Run periodically polls the service account token secret, as described by the
// CLI flags, and looks up the service account.  If the service account's expiry,
// minus a threshold, is in the past, rotate the token.  Repeat until the context
// is cancelled.
func (r *TokenRotator) Run(ctx context.Context) error {
	// Grad the Kubernetes REST config.
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	// Create a cache.
	cacheOptions := cache.Options{
		DefaultNamespaces: map[string]cache.Config{
			r.Namespace: cache.Config{},
		},
	}

	cache, err := cache.New(config, cacheOptions)
	if err != nil {
		return err
	}

	go func() {
		_ = cache.Start(ctx)
	}()

	// Create a Kubernetes client.
	clientOptions := crclient.Options{
		Cache: &crclient.CacheOptions{
			Reader: cache,
		},
	}

	cli, err := crclient.New(config, clientOptions)
	if err != nil {
		return err
	}

	// Force the client to only use the local namespace for security.
	nscli := crclient.NewNamespacedClient(cli, r.Namespace)

	ticker := time.NewTicker(r.TokenPollingDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.loadToken(ctx, nscli); err != nil {
				log.Log.Error(err, "failed to load token")
				continue
			}

			info, err := r.introspectToken(ctx)
			if err != nil {
				log.Log.Error(err, "failed to perform token introspection")
				continue
			}

			timeLeft := time.Until(info.expiry.Add(-r.TokenExpiryThreshold))

			if timeLeft > 0 {
				log.Log.Info("token rotation skipped", "in", timeLeft.String())
				continue
			}

			if err = r.rotateToken(ctx, nscli, info); err != nil {
				log.Log.Error(err, "failed to rotate token")
				continue
			}

			log.Log.Info("token rotated successfully")
		}
	}
}
