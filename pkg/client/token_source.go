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

package client

import (
	"os"
	"strings"

	"github.com/spf13/pflag"
)

// TokenSource sources a token from somewhere.
type TokenSource interface {
	// AddFlags adds any flags to the given CLI flagset.
	AddFlags(f *pflag.FlagSet)
	// Token returns the current token.  It is expected to be called
	// on each request to get the most up to date version to handle
	// token rotation.
	Token() (string, error)
}

// FileTokenSource loads a token from a file.  This is typically used
// for CLI based applications, and Kubernetes ones where a secret is
// mounted in the pod.
type FileTokenSource struct {
	TokenFile string
}

func NewFileTokenSource() *FileTokenSource {
	return &FileTokenSource{}
}

func (l *FileTokenSource) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&l.TokenFile, "token-file", l.TokenFile, "Where to source the access token from.")
}

func (l *FileTokenSource) Token() (string, error) {
	data, err := os.ReadFile(l.TokenFile)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// VariableTokenSource loads the token directly from a variable.  This is
// typically used in Kubernetes where the token is sourced directly from
// a secret.
type VariableTokenSource struct {
	token string
}

func NewVariableTokenSource(token string) *VariableTokenSource {
	return &VariableTokenSource{
		token: token,
	}
}

func (l *VariableTokenSource) AddFlags(f *pflag.FlagSet) {
}

func (l *VariableTokenSource) Update(token string) {
	l.token = token
}

func (l *VariableTokenSource) Token() (string, error) {
	return l.token, nil
}
