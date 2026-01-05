.PHONY: all deps build install test clean fmt vet install-hooks

# Default target
all: build

# Download dependencies
deps:
	go mod download
	go mod tidy

# Build the binary
build:
	go build -o shells .

# Install to GOPATH/bin
install:
	go install

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f shells

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
	go build -race -o shells .

# Install git hooks for development
install-hooks:
	@echo "Installing git hooks..."
	@cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
	@cp scripts/git-hooks/pre-push .git/hooks/pre-push
	@chmod +x .git/hooks/pre-commit .git/hooks/pre-push
	@echo "Git hooks installed successfully."