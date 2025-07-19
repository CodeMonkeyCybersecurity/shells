# WebScan CLI

A production-ready Cobra CLI tool for web application security testing and bug bounty automation. WebScan integrates multiple security tools into a unified platform with distributed scanning capabilities, result aggregation, and deployment on HashiCorp Nomad.

## Features

- **Modular Architecture**: Clean architecture with dependency injection and plugin system
- **Multiple Scanner Integration**:
  - **Network & Infrastructure**: Nmap (port scanning, service detection), SSL/TLS analysis
  - **Web Application Security**: OWASP ZAP, Nikto, directory/file discovery
  - **Advanced Reconnaissance**: httpx (HTTP probing), DNS enumeration
  - **Vulnerability Assessment**: Nuclei (template-based scanning), OpenVAS
  - **OAuth2/Authentication Testing**: Comprehensive OAuth2/OIDC security assessment
  - **API Security**: GraphQL introspection, batching attacks, complexity analysis
  - **JavaScript Analysis**: Secret extraction, library vulnerability detection, DOM XSS sinks
  - **Workflow Engine**: Complex multi-stage scanning pipelines
- **Distributed Scanning**: Redis-based job queue with worker pools
- **Observability**: OpenTelemetry integration with structured logging via otelzap
- **Result Management**: Normalized result schema with SQLite storage (lightweight, embedded database)
- **Deployment Ready**: Docker containers and Nomad job specifications
- **Security Features**: Rate limiting, scope validation, audit trails

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/webscan-cli
cd webscan-cli

# Install dependencies
make deps

# Build the binary
make build

# Install to $GOPATH/bin
make install
```

## Quick Start

### Local Development

```bash
# Start infrastructure with Docker Compose
make docker-compose-up

# Run a worker
make worker

# In another terminal, run scans
webscan scan port example.com
webscan scan ssl example.com:443
webscan scan full example.com
```

### Configuration

Create a `.webscan.yaml` in your home directory or use `--config` flag:

```yaml
logger:
  level: info
  format: json

database:
  driver: sqlite3
  dsn: "webscan.db"  # SQLite database file path

redis:
  addr: localhost:6379

worker:
  count: 3
  queue_poll_interval: 5s

tools:
  nmap:
    binary_path: /usr/bin/nmap
    profiles:
      default: "-sS -sV -O"
      fast: "-T4 -F"
      thorough: "-sS -sV -sC -O -A"
```

## CLI Commands

### Scanning

```bash
# Port scanning
webscan scan port example.com --profile fast --ports 1-1000

# SSL/TLS analysis
webscan scan ssl example.com --port 443

# Web application scanning
webscan scan web https://example.com --depth 3

# Vulnerability scanning
webscan scan vuln example.com

# DNS enumeration
webscan scan dns example.com

# Directory discovery
webscan scan dir https://example.com --wordlist common.txt

# OAuth2/OIDC Security Testing
webscan scan oauth2 https://example.com --client-id your-client-id --redirect-uri https://example.com/callback

# Advanced HTTP Reconnaissance
webscan scan httpx example.com --follow-redirects --probe-all-ips

# Nuclei Template-based Vulnerability Scanning
webscan scan nuclei example.com --severity critical,high --tags oauth,jwt,auth

# JavaScript Security Analysis
webscan scan js https://example.com

# GraphQL Security Testing
webscan scan graphql https://example.com/graphql --auth-header "Authorization: Bearer token"

# Comprehensive scan
webscan scan full example.com
```

### Workflow-Based Scanning

```bash
# List available workflows
webscan workflow list

# Run comprehensive security assessment
webscan workflow run comprehensive example.com

# OAuth2-focused security testing
webscan workflow run oauth2_focused https://oauth.example.com

# API security assessment
webscan workflow run api_security https://api.example.com
```

### Results Management

```bash
# List recent scans
webscan results list --limit 20

# Get specific scan results
webscan results get <scan-id>

# Export results
webscan results export <scan-id> --format json --output results.json
webscan results export <scan-id> --format csv --output results.csv
webscan results export <scan-id> --format html --output report.html

# Get summary statistics
webscan results summary --days 7
```

### Configuration

```bash
# Create scan profile
webscan config profile create aggressive --description "Aggressive scanning profile"

# Manage scope
webscan config scope add "*.example.com"
webscan config scope add "192.168.1.0/24"
webscan config scope list

# Configure tools
webscan config tool nmap --timeout 60m
webscan config tool zap --api-key your-api-key
```

### Scheduling

```bash
# Schedule periodic scans
webscan schedule create example.com --cron "0 0 * * *" --type full

# List schedules
webscan schedule list

# Delete schedule
webscan schedule delete <schedule-id>
```

### Deployment

```bash
# Deploy to Nomad
webscan deploy create --workers 5 --datacenter dc1

# Scale workers
webscan deploy scale 10

# Check deployment status
webscan deploy status

# Stop deployment
webscan deploy stop
```

## Advanced Pentesting Capabilities

WebScan CLI includes state-of-the-art security testing modules designed for serious penetration testers and bug bounty hunters:

### OAuth2/OIDC Security Testing
- **Authorization Code Replay**: Tests for single-use code enforcement
- **Redirect URI Validation Bypass**: 10+ bypass techniques including subdomain takeover, unicode, and protocol downgrade
- **PKCE Downgrade Attacks**: Tests for PKCE requirement enforcement
- **State Parameter Validation**: Entropy and binding validation
- **Token Leakage Detection**: Referrer header and URL fragment exposure
- **JWT Security**: Algorithm confusion, signature bypass, weak secrets
- **CSRF Protection**: Tests for proper CSRF token implementation

### GraphQL Security Assessment
- **Introspection Analysis**: Schema exposure and sensitive type detection
- **Batching Attacks**: Array and alias-based batching for rate limit bypass
- **Query Depth Limiting**: Deep nesting DoS attack testing
- **Query Complexity**: Resource exhaustion via complex queries
- **Field Duplication**: Redundant field processing detection
- **Information Disclosure**: Error message analysis for sensitive data
- **SQL Injection**: GraphQL-specific injection testing
- **Authentication Bypass**: CSRF and missing authorization testing

### JavaScript Security Analysis
- **Secret Extraction**: AWS keys, Google API keys, GitHub tokens, JWT tokens
- **Vulnerable Library Detection**: jQuery, Angular, Bootstrap, Lodash with CVE mapping
- **DOM XSS Sink Detection**: innerHTML, eval, setTimeout with user input flow analysis
- **API Endpoint Discovery**: Fetch, Axios, AJAX call extraction
- **OAuth2 Token Analysis**: Client secrets, hardcoded tokens, weak randomness
- **URL Extraction**: Admin paths, config files, S3 buckets, internal URLs

### Advanced HTTP Reconnaissance (httpx Integration)
- **Technology Stack Detection**: 20+ web technologies with security implications
- **Security Header Analysis**: Missing CSP, HSTS, X-Frame-Options detection
- **Subdomain Takeover Detection**: CNAME analysis for vulnerable services
- **Certificate Analysis**: Wildcard certificates, hostname mismatches
- **OAuth2 Endpoint Discovery**: .well-known, authorization, token endpoints
- **API Documentation Discovery**: Swagger, OpenAPI, GraphQL endpoints

### Nuclei Template Integration
- **10,000+ Security Templates**: Community-driven vulnerability detection
- **OAuth2-Specific Templates**: JWT vulnerabilities, client secret exposure
- **API Security Templates**: GraphQL introspection, REST API misconfigurations
- **Cloud Security Templates**: AWS, GCP, Azure misconfiguration detection
- **Custom Template Support**: Organization-specific vulnerability patterns

## Architecture

### Core Components

1. **Job Queue**: Redis-based priority queue for scan jobs
2. **Worker Pool**: Scalable workers that process scan jobs
3. **Plugin System**: Modular scanner integration
4. **Result Store**: PostgreSQL/SQLite for persistent storage
5. **Telemetry**: OpenTelemetry for distributed tracing and metrics

### Security Features

- **Rate Limiting**: Configurable per-target rate limits
- **Scope Validation**: Whitelist-based target validation
- **Authentication**: API key and JWT support
- **Audit Logging**: Complete activity trails

## Development

### Project Structure

```
webscan-cli/
├── cmd/              # CLI commands
├── internal/         # Internal packages
│   ├── config/      # Configuration
│   ├── core/        # Core interfaces
│   ├── database/    # Storage implementation
│   ├── jobs/        # Job queue
│   ├── logger/      # Structured logging
│   ├── plugins/     # Scanner plugins
│   ├── telemetry/   # OpenTelemetry
│   └── worker/      # Worker implementation
├── pkg/             # Public packages
│   ├── scanner/     # Scanner interface
│   └── types/       # Domain types
├── deployments/     # Deployment configs
│   ├── docker/      # Docker files
│   └── nomad/       # Nomad job specs
└── test/            # Tests

```

### Adding a New Scanner

1. Implement the `core.Scanner` interface:

```go
type Scanner interface {
    Name() string
    Type() types.ScanType
    Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error)
    Validate(target string) error
}
```

2. Register with the plugin manager:

```go
pluginManager.Register(yourScanner)
```

### Running Tests

```bash
# Unit tests
make test

# Integration tests
make test-integration

# Benchmarks
make bench

# Coverage report
make coverage
```

## Deployment

### Docker

```bash
# Build image
make docker-build

# Push to registry
make docker-push

# Run with Docker Compose
docker-compose -f deployments/docker/docker-compose.yml up
```

### Nomad

```bash
# Deploy job
nomad job run deployments/nomad/webscan.nomad

# Check status
nomad job status webscan

# Scale workers
nomad job scale webscan workers 10
```

## Monitoring

### Metrics

- Scan duration and success rate
- Finding counts by severity
- Worker utilization
- Queue depth

### Distributed Tracing

OpenTelemetry traces provide visibility into:
- Scan execution flow
- Tool performance
- Database queries
- External API calls

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run `make lint` and `make test`
6. Submit a pull request

## License

MIT License - see LICENSE file for details