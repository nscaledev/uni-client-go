# Some bits about go.
GOPATH := $(shell go env GOPATH)
GOBIN := $(if $(shell go env GOBIN),$(shell go env GOBIN),$(GOPATH)/bin)

# Defines the linter version.
LINT_VERSION=v1.61.0

# Perform linting.
# This must pass or you will be denied by CI.
.PHOMY: lint
lint: $(GENDIR)
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	$(GOBIN)/golangci-lint run ./...

# Perform license checking.
# This must pass or you will be denied by CI.
.PHONY: license
license:
	@go install github.com/unikorn-cloud/core/hack/check_license@main
	$(GOBIN)/check_license
