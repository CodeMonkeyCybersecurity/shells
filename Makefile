.PHONY: all deps build install test clean fmt vet

# Default target
all: build

# Download dependencies
deps:
	go mod download
	go mod tidy

# Build the binary
build:
	go build -o artemis .

# Install to GOPATH/bin
install:
	go install

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f artemis

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Run all checks
check: fmt vet test

# Development build with race detection
dev:
	go build -race -o artemis .