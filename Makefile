.PHONY: build build-all test lint sdk-test sdk-run clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY_NAME = epack-tool-validate
LDFLAGS = -s -w -X main.Version=$(VERSION)

# Lint code (downloads golangci-lint binary to match CI)
GOLANGCI_LINT_VERSION := v2.9.0
GOLANGCI_LINT := ./bin/golangci-lint

$(GOLANGCI_LINT):
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b ./bin $(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)-darwin-arm64 .

test:
	go test -race ./...

# SDK development commands
sdk-test:
	epack sdk test ./$(BINARY_NAME)

sdk-run:
	epack sdk run ./$(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*
