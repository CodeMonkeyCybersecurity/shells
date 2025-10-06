# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**shells** is a security scanning tool built in Go by Code Monkey Cybersecurity (ABN 77 177 673 061).

**Motto**: "Cybersecurity. With humans."

### Philosophy

- **Human-centric**: Transparent error handling, actionable output, addresses barriers to entry, encourages end-user education and self-efficacy, feminist principles (informed consent), safe, effective, high-quality
- **Evidence-based**: Accepts fallibilism, error correction, value for time, value for money, verifiable results
- **Sustainable innovation**: Maintainable code, comprehensive documentation, iterative improvement, incident response ready, incorporates recent research and best practice
- **Collaboration and listening**: Built by ethical hackers for ethical hackers, transparent decision making, ownership and accountability, open source

**Purpose**: Designed for bug bounty hunters and security researchers to automate the vulnerability discovery and reporting pipeline through distributed scanning while maintaining ethical practices and human oversight.

## Working with Claude

### Collaboration Principles

**Adversarial Collaboration**: Claude works as a partner in an adversarially collaborative process, following your lead and providing fact-based targeted criticism. This means:

- Looking for what works AND what doesn't
- Providing honest assessment without sugar-coating
- Offering actionable improvements, not just observations
- Challenging assumptions when evidence suggests alternatives
- Staying focused on sustainable, maintainable solutions

**Iterative Improvement Process**:

A common workflow is to ask Claude to:
> "Please have a look through Shells and come talk to me as an adversarial collaborator, what is good, what's not great, what's broken, what are we not thinking about, etc. Then, please fix all P0 P1 P2 P3 issues"

This triggers a comprehensive analysis followed by prioritized fixes.

**Conversation Context**:

When looking for context, Claude should:
1. **First check previous conversations** to see if we've discussed the subject before
2. **Pick up from where we most recently left off** instead of starting from scratch
3. Avoid repeating work or analyses already completed
4. Reference past decisions and their reasoning when relevant

### Communication Style

- **Direct and concise**: No unnecessary preamble or filler
- **Evidence-based**: Cite specific code, line numbers, test results
- **Actionable**: Every criticism includes a concrete fix
- **Human-focused**: Remember this tool serves security researchers who need reliable results

## Common Development Commands

### Build and Test
```bash
make deps          # Download dependencies and run go mod tidy
make build         # Build the binary (./shells)
make dev           # Build with race detection for development
make test          # Run all tests
make check         # Run fmt, vet, and test (use before committing)
make fmt           # Format code with gofmt
make vet           # Check for potential issues
make clean         # Remove built binary
make install       # Install to $GOPATH/bin
```

### Running Tests
```bash
# Run all tests
make test

# Run specific package tests
go test ./pkg/scim/...
go test ./pkg/smuggling/...

# Run with verbose output
go test -v ./...

# Run with race detection
go test -race ./...
```

## Architecture Overview

### Directory Structure
- **`/cmd/`** - CLI commands (each file implements a Cobra command)
  - All new commands should follow the existing pattern in scan.go
  - Use spf13/cobra for command structure
  - Add appropriate flags and comprehensive help text

- **`/internal/`** - Internal packages (not exposed externally)
  - `config/` - Configuration management using Viper
  - `database/` - Database abstraction layer (SQLite)
  - `jobs/` - Redis-based job queue implementation
  - `worker/` - Worker pool for distributed scanning
  - `plugins/` - Scanner plugin implementations
  - `nomad/` - HashiCorp Nomad integration for deployment

- **`/pkg/`** - Public packages that can be imported
  - `auth/` - Authentication testing modules (OAuth2, SAML, WebAuthn)
  - `discovery/` - Asset discovery (DNS, hosting detection)
  - `scanners/` - Specific scanner implementations
  - `types/` - Common type definitions used across packages

### Key Design Patterns

1. **Worker-Based Architecture**
   - Uses Redis for job queuing
   - Configurable worker pools for parallel scanning
   - Job status tracking in SQLite

2. **Plugin System**
   - Scanners are implemented as plugins in `/internal/plugins/`
   - Each plugin implements the core.Plugin interface
   - Plugins are registered and managed by the worker system

3. **Configuration**
   - Uses `.shells.yaml` for configuration
   - Viper for configuration management
   - Environment variables override config file values

4. **Database**
   - Uses SQLite for lightweight, embedded storage
   - Uses sqlx for database operations
   - Migrations handled automatically on startup

## Security Considerations

This is a security tool - when contributing:
- **NEVER** add code that could be used maliciously
- Focus on defensive security and vulnerability discovery
- Respect rate limits and terms of service
- Always require explicit user authorization for scans
- Never commit credentials or sensitive data
- Test only against authorized targets

## Adding New Features

### Adding a New Scanner Command
1. Create a new file in `/cmd/` (e.g., `cmd/mynewscanner.go`)
2. Follow the pattern from existing commands like `scan.go`
3. Register the command in the init() function
4. Add configuration options to the config struct if needed
5. Implement the scanner logic in `/internal/plugins/` or `/pkg/scanners/`
6. Update README.md with usage examples

### Adding a New Scanner Plugin
1. Create a new directory in `/internal/plugins/`
2. Implement the `core.Plugin` interface
3. Add configuration struct in `/internal/config/`
4. Register the plugin in the worker initialization
5. Add tests for the new functionality

## Testing Guidelines

- Write tests for all new functionality
- Place test files next to implementation files with `_test.go` suffix
- Use table-driven tests where appropriate
- Mock external dependencies
- Ensure tests are safe and don't make external network calls

## Code Style

- Use `gofmt` for formatting (run `make fmt`)
- Follow standard Go conventions
- Add comments for all exported functions
- Keep functions focused and small
- Use meaningful variable and function names
- Handle errors explicitly - don't ignore them

## Intelligent Asset Discovery & Point-and-Click Mode

**shells** is designed as a comprehensive "point and click" security scanner. Run `shells cybermonkey.net.au` and the tool automatically:

1. **Discovers everything** related to the target
2. **Tests everything** for vulnerabilities
3. **Saves everything** to PostgreSQL for historical analysis

The target can be:
- **Company name**: "Acme Corporation"
- **Email address**: "admin@acme.com"
- **Domain**: "acme.com"
- **IP address**: "192.168.1.1"
- **IP range**: "192.168.1.0/24"

### Comprehensive Asset Discovery Pipeline

When you run `shells [target]`, the tool executes the FULL discovery pipeline:

#### Phase 1: Organization Footprinting
- **WHOIS Analysis**: Organization name, registrant email, admin contact, technical contact
- **Certificate Transparency**: Find ALL domains with same certificate, same issuer, same organization
- **Email-based Discovery**: Find domains registered to same email address
- **Related Domain Discovery**: Same organization, same registrant, same name servers

#### Phase 2: Network Discovery
- **Subdomain Enumeration**:
  - DNS brute force (wordlist-based)
  - Certificate transparency logs (crt.sh, Censys)
  - Search engine dorking (Google, Bing, Shodan)
  - DNS records (MX, TXT, NS, SOA for clues)
- **Adjacent IP Scanning**: Scan neighboring IPs in /24 subnet (e.g., if target is 192.168.1.50, scan 192.168.1.0-255)
- **Reverse DNS**: Find other domains hosted on same IP
- **Port Scanning**: Scan all 65535 ports (or top 1000 for speed)
- **Service Fingerprinting**: Nmap version detection on all open ports

#### Phase 3: Application Discovery
- **Deep Web Crawling** (MaxDepth: 3):
  - Find login pages, registration forms
  - Discover API endpoints (REST, GraphQL, SOAP)
  - Locate admin panels, debug pages
  - Identify file upload capabilities
  - Map authentication flows
- **Technology Stack Detection**:
  - Framework identification (Django, Rails, Laravel, Express)
  - CMS detection (WordPress, Drupal, Joomla)
  - Cloud provider detection (AWS, Azure, GCP)
  - CDN and WAF identification

### Comprehensive Vulnerability Testing

After discovery, shells automatically tests EVERYTHING for vulnerabilities:

#### Authentication Testing
- **SAML**: Golden SAML, XML signature wrapping, assertion manipulation
- **OAuth2/OIDC**: JWT algorithm confusion, PKCE bypass, state validation, scope escalation
- **WebAuthn/FIDO2**: Virtual authenticator attacks, credential substitution, challenge reuse
- **Session Handling**: Fixation, hijacking, weak tokens

#### API Security Testing
- **GraphQL**: Introspection, injection, DoS via nested queries, batching attacks
- **REST**: Authentication bypass, rate limiting, IDOR on endpoints
- **SOAP**: XXE, WSDL disclosure, injection

#### Access Control Testing
- **IDOR**: Sequential ID enumeration, UUID prediction
- **Horizontal Privilege Escalation**: Access other users' resources
- **Vertical Privilege Escalation**: Admin function access
- **SCIM**: Unauthorized provisioning, filter injection, bulk operations

#### Injection Testing
- **SQL Injection**: Error-based, blind, time-based, out-of-band
- **XSS**: Reflected, stored, DOM-based
- **SSRF**: Internal network access, cloud metadata exploitation

#### Business Logic Testing
- **Payment Manipulation**: Price tampering, currency mismatch
- **Workflow Bypass**: Step skipping, state manipulation
- **Rate Limiting**: Brute force protection, account enumeration

### Temporal Snapshots & Historical Analysis

**CRITICAL**: All scan results are saved to PostgreSQL with temporal tracking:

- **First Scan**: Baseline snapshot of discovered assets and vulnerabilities
- **Subsequent Scans**: Compare to previous snapshots, track:
  - New assets discovered (new subdomains, new IPs, new services)
  - Assets that disappeared (services shut down, domains expired)
  - New vulnerabilities found
  - Fixed vulnerabilities (no longer present)
  - Changes in service versions, SSL certificates, DNS records

#### Database Schema Supports:
- Asset discovery history (when first seen, last seen, status changes)
- Vulnerability lifecycle (discovered date, fixed date, reappeared date)
- Service version tracking (detect outdated services over time)
- Certificate expiry monitoring
- Port change detection

#### Query Historical Data:
```bash
# View all scans for a target
shells results query --target example.com --show-history

# Compare current vs last scan
shells results diff scan-12345 scan-12346

# Find new vulnerabilities since last month
shells results query --target example.com --since 30d --status new

# Track vulnerability fix rate
shells results stats --target example.com --metric fix-rate
```

### Technical Implementation Notes

- The main command should be in `cmd/root.go` as the default action
- Asset discovery logic should be in `internal/discovery/`
- Use worker pools for parallel scanning of discovered assets
- Maintain an asset graph showing relationships between discovered targets
- Cache discovery results to avoid redundant work
- Support resuming interrupted scans
- Provide real-time progress updates

### Discovery Modules to Implement

1. **CompanyDiscovery**: Search engines, certificate logs, WHOIS
2. **DomainDiscovery**: DNS enumeration, subdomain discovery
3. **NetworkDiscovery**: IP range scanning, service discovery
4. **TechnologyDiscovery**: Framework detection, service fingerprinting
5. **AssetRelationshipMapper**: Build relationships between discovered assets

### Command Structure

- `shells [target]` - Full automated discovery and testing
- Maintain existing granular commands: `shells scan`, `shells logic`, etc.
- Add `shells discover [target]` for discovery-only mode
- Add `shells resume [scan-id]` to resume interrupted scans

## Common Workflows

### Point-and-Click Usage
```bash
# Discover and test everything related to a company
shells "Acme Corporation"

# Discover and test everything related to a domain
shells acme.com

# Discover and test everything in an IP range
shells 192.168.1.0/24

# Discovery only (no testing)
shells discover acme.com

# Resume interrupted scan
shells resume scan-12345
```

### Database Operations
- Database migrations are handled automatically
- Uses SQLite for lightweight, embedded storage
- Database file is created automatically on first run 

## Logging Standards

**CRITICAL: ALL output must use structured otelzap logging - no fmt.Print/Printf/Println anywhere**

### Structured Logging with OpenTelemetry

shells uses **otelzap** (OpenTelemetry + Zap) for ALL output, including user-facing messages. This provides:
- Distributed tracing across services
- Structured JSON logs for parsing/analysis
- Machine-readable output for automation
- Consistent log levels and formatting
- Integration with observability platforms

### Logger Initialization

Every package should initialize a logger with a component name:

```go
import "github.com/CodeMonkeyCybersecurity/shells/internal/logger"

// In main/command functions
log, err := logger.New(cfg.Logger)
if err != nil {
    return fmt.Errorf("failed to initialize logger: %w", err)
}
log = log.WithComponent("scanner")
```

### Logging Patterns

#### User-Facing Messages (CLI Output)

Use `logger.Info()` for user-facing messages (NOT fmt.Print):

```go
// ❌ WRONG - Never use fmt.Print
fmt.Println("✅ Scan completed!")
fmt.Printf("Found %d vulnerabilities\n", count)

// ✅ CORRECT - Always use structured logging
log.Info("✅ Scan completed!")
log.Infow("Scan results",
    "vulnerabilities_found", count,
    "scan_duration", duration,
    "target", target,
)
```

#### Background/Service Logging

Use structured fields for machine-parseable data:

```go
// Informational logging
log.Infow("Worker started",
    "worker_id", id,
    "queue", queue,
    "component", "worker",
)

// Warning logging
log.Warnw("Rate limit approaching",
    "current_rate", rate,
    "limit", maxRate,
    "component", "api",
)

// Error logging
log.Errorw("Database query failed",
    "error", err,
    "query", query,
    "duration_ms", duration,
    "component", "database",
)
```

#### Progress and Status Updates

Use structured logging for progress (NOT progress bars):

```go
// ❌ WRONG - No ANSI progress bars
fmt.Printf("\r[████░░░░] 50%%")

// ✅ CORRECT - Structured progress logging
log.Infow("Scan progress",
    "phase", "discovery",
    "progress_pct", 50,
    "assets_found", assetCount,
    "elapsed_seconds", elapsed.Seconds(),
)
```

#### Interactive Prompts

Even interactive prompts should log structured data:

```go
// Before prompting user
log.Infow("API key configuration needed",
    "api", "CIRCL",
    "prompt", "interactive",
    "component", "credentials",
)

// After user response
log.Infow("API key configured",
    "api", "CIRCL",
    "source", "user_input",
    "component", "credentials",
)
```

### Log Levels

- **Debug** (`log.Debug`, `log.Debugw`): Development/troubleshooting details
- **Info** (`log.Info`, `log.Infow`): Normal operations, user messages, status updates
- **Warn** (`log.Warn`, `log.Warnw`): Degraded functionality, recoverable errors
- **Error** (`log.Error`, `log.Errorw`): Errors that prevent operations

### Migration Rules

When migrating from fmt.Print to otelzap:

1. **User-facing messages** → `log.Info()` or `log.Infow()`
2. **Error messages** → `log.Errorw()` with structured error field
3. **Debug output** → `log.Debugw()` with context fields
4. **Progress bars** → Periodic `log.Infow()` with progress percentage
5. **Interactive prompts** → Log intent before/after, use `log.Info()` for messages

### Debugging Tips

- Use structured logging with otelzap for all output (no fmt.Print)
- Enable debug logging: `--log-level debug`
- Use OpenTelemetry tracing for distributed operations
- Check worker logs for scanning issues
- Monitor Redis queue for job status
- Parse JSON logs for automation: `shells scan example.com --log-format json | jq`

## Important Files

- `main.go` - Entry point
- `cmd/root.go` - Root command setup
- `internal/config/config.go` - Configuration structures
- `.shells.yaml` - Main configuration file
- `internal/worker/worker.go` - Worker pool implementation
- `internal/jobs/jobs.go` - Job queue management

## Enhanced Security Scanning Features

### SCIM Vulnerability Testing
```bash
# Discover SCIM endpoints
shells scim discover https://example.com

# Run comprehensive SCIM security tests
shells scim test https://example.com/scim/v2 --test-all
shells scim test https://example.com/scim/v2 --test-filters --test-auth

# Test provisioning vulnerabilities
shells scim provision https://example.com/scim/v2/Users --dry-run
shells scim provision https://example.com/scim/v2/Users --test-privesc
```

### HTTP Request Smuggling Detection
```bash
# Detect smuggling vulnerabilities
shells smuggle detect https://example.com
shells smuggle detect https://example.com --technique cl.te --differential

# Exploit discovered vulnerabilities
shells smuggle exploit https://example.com --technique te.cl
shells smuggle exploit https://example.com --cache-poison
```

### Enhanced Results Querying
```bash
# Query findings with advanced filters
shells results query --severity critical
shells results query --tool scim --type "SCIM_UNAUTHORIZED_ACCESS"
shells results query --search "injection" --limit 20
shells results query --target example.com --days 7

# View statistics and analytics
shells results stats
shells results stats --output json

# Search findings with full-text search
shells results search --term "Golden SAML" --limit 10
shells results search --term "JWT algorithm confusion"

# Get recent critical findings
shells results recent --severity critical --limit 20

# Export results in various formats
shells results export [scan-id] --format json
shells results export [scan-id] --format csv --output findings.csv
shells results export [scan-id] --format html --output report.html
```

### Key Vulnerability Types

**SCIM Vulnerabilities:**
- Unauthorized user provisioning
- Filter injection attacks
- Bulk operation abuse
- Privilege escalation via PATCH
- Schema information disclosure

**Request Smuggling Vulnerabilities:**
- CL.TE (Content-Length Transfer-Encoding) desync
- TE.CL (Transfer-Encoding Content-Length) desync
- TE.TE (Transfer-Encoding Transfer-Encoding) desync
- HTTP/2 request smuggling
- Cache poisoning via smuggling
- WAF bypass techniques

## Authentication Testing

The authentication testing framework provides comprehensive security testing for modern authentication protocols and identity systems.

### Available Commands

#### `shells auth discover --target <url>`
Discovers authentication endpoints and methods for a target:
- SAML endpoints and metadata discovery
- OAuth2/OIDC configuration endpoint detection
- WebAuthn/FIDO2 endpoint identification
- Federation provider enumeration
- Trust relationship mapping
- Protocol capability analysis

#### `shells auth test --target <url> --protocol <protocol>`
Runs comprehensive security tests against authentication systems:
- **SAML**: Golden SAML attacks, XML signature wrapping, signature bypass, assertion manipulation
- **OAuth2/OIDC**: JWT attacks, flow vulnerabilities, PKCE bypass, state validation
- **WebAuthn/FIDO2**: Virtual authenticator attacks, credential manipulation, challenge reuse
- **Federation**: Confused deputy attacks, trust misconfigurations, IdP spoofing

#### `shells auth chain --target <url>`
Finds authentication bypass chains and attack paths:
- Cross-protocol vulnerability chaining
- Authentication downgrade path analysis
- Federation confusion attack detection
- Multi-step bypass scenario identification
- Attack path visualization

#### `shells auth all --target <url>`
Runs comprehensive authentication security analysis including discovery, testing, and chain analysis with detailed reporting.

### Protocol-Specific Testing Capabilities

#### SAML Security Testing
- **Golden SAML Detection**: Tests for signature validation bypass allowing forged assertions
- **XML Signature Wrapping (XSW)**: Multiple XSW attack variants including comment-based and transform-based attacks
- **Signature Validation Bypass**: Tests for weak signature validation implementations
- **Assertion Manipulation**: Malicious assertion injection and modification testing
- **Metadata Poisoning**: SAML metadata manipulation and injection attacks
- **Replay Attack Detection**: Tests for proper timestamp and nonce validation

#### OAuth2/OIDC Security Testing
- **JWT Algorithm Confusion**: Tests for 'none' algorithm and RS256 to HS256 confusion attacks
- **Key Confusion Attacks**: RS256 to HS256 key confusion using public keys as HMAC secrets
- **PKCE Bypass Testing**: Tests for missing or weak PKCE implementation
- **State Parameter Validation**: CSRF protection through state parameter analysis
- **Redirect URI Manipulation**: Open redirect and subdomain takeover testing
- **Scope Escalation**: Tests for improper scope validation and privilege escalation
- **Authorization Code Injection**: Tests for code injection vulnerabilities
- **Mix-Up Attack Detection**: Tests for authorization server confusion attacks

#### WebAuthn/FIDO2 Security Testing
- **Virtual Authenticator Attacks**: Comprehensive malicious authenticator simulation
- **Credential Substitution**: Tests for credential replacement and manipulation
- **Challenge Reuse Attacks**: Tests for proper challenge uniqueness and expiration
- **Origin Validation Bypass**: Cross-origin WebAuthn operation testing
- **Attestation Bypass**: Tests for weak attestation validation
- **User Verification Bypass**: Tests for UV flag manipulation and bypass
- **Counter Manipulation**: Tests for proper authenticator counter validation
- **Parallel Session Attacks**: Tests for session confusion and binding issues

#### Federation Security Testing
- **Confused Deputy Attacks**: Tests for cross-IdP assertion acceptance vulnerabilities
- **Trust Relationship Analysis**: Detection of overly broad trust configurations
- **IdP Spoofing Detection**: Tests for IdP identity validation weaknesses
- **Assertion Manipulation**: Cross-federation assertion modification testing
- **Cross-Domain Vulnerabilities**: Tests for domain boundary crossing attacks
- **Provider Confusion**: Tests for multiple provider identity confusion
- **Token Reuse Analysis**: Tests for cross-provider token reuse vulnerabilities

### Advanced Attack Chain Detection

#### Cross-Protocol Attack Chains
The framework detects complex attack chains spanning multiple authentication protocols:
- **WebAuthn to Password Downgrade**: Bypass strong authentication through account recovery
- **OAuth2 to SAML Confusion**: Exploit protocol confusion for authentication bypass
- **SAML to Local Account Takeover**: Use SAML vulnerabilities for complete account control
- **JWT to Session Upgrade**: Forge JWT tokens for privilege escalation
- **Federation Bypass Chains**: Exploit trust relationships for authentication bypass

#### Attack Vector Generation
Generates practical attack payloads for discovered vulnerabilities:
- **Malicious JWT Tokens**: Algorithm confusion, claim manipulation, signature bypass
- **Golden SAML Assertions**: Properly formatted malicious SAML assertions
- **WebAuthn Attack Payloads**: Virtual authenticator responses and challenges
- **OAuth2 Flow Manipulation**: Malicious authorization requests and responses
- **Federation Confusion Payloads**: Cross-provider assertion manipulation

### Enhanced Reporting and Analysis

#### Comprehensive Vulnerability Analysis
- **Severity Assessment**: CVSS scoring and risk categorization
- **Evidence Collection**: Detailed technical evidence for each vulnerability
- **Remediation Guidance**: Specific mitigation steps and best practices
- **Attack Path Visualization**: Clear representation of exploit chains
- **Compliance Mapping**: Alignment with security standards and frameworks

#### Database Integration
All authentication testing results are automatically stored with:
- Vulnerability details and technical evidence
- Attack chain analysis and step-by-step breakdown
- Remediation recommendations and priority levels
- CVSS scores and CWE mappings
- Timestamp and scan metadata
- Historical trend analysis

### Example Usage

```bash
# Discover authentication methods and endpoints
shells auth discover --target https://example.com --verbose

# Test SAML implementation for Golden SAML and XSW attacks
shells auth test --target https://example.com --protocol saml --output json

# Analyze JWT tokens for algorithm confusion and key attacks
shells auth test --target "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --protocol jwt

# Test WebAuthn implementation with virtual authenticator
shells auth test --target https://example.com --protocol webauthn

# Find cross-protocol attack chains
shells auth chain --target https://example.com --max-depth 5

# Comprehensive authentication security analysis
shells auth all --target https://example.com --output json --save-report auth-report.json

# Query stored authentication findings
shells results query --tool auth --severity CRITICAL
shells results stats --tool auth
```

### Integration with Core Security Framework

#### Database Query Integration
```bash
# Query authentication-specific findings
shells results query --tool saml --severity HIGH
shells results query --tool oauth2 --type "JWT Vulnerability"
shells results query --tool webauthn --target "example.com"
shells results query --tool federation --from-date "2024-01-01"

# Generate authentication security statistics
shells results stats --tool auth
shells results recent --tool saml --limit 10
shells results search --term "Golden SAML"
```

#### Advanced Finding Analysis
- **Cross-Reference Analysis**: Correlate findings across different authentication protocols
- **Temporal Analysis**: Track authentication vulnerabilities over time
- **Impact Assessment**: Comprehensive risk analysis for authentication weaknesses
- **Remediation Tracking**: Monitor fix implementation and verification

### Authentication Vulnerability Types

**SAML Vulnerabilities:**
- Golden SAML signature bypass
- XML Signature Wrapping (XSW) attacks
- Assertion manipulation and injection
- Metadata poisoning
- Replay attack vulnerabilities
- Weak signature validation

**OAuth2/OIDC Vulnerabilities:**
- JWT algorithm confusion (none, RS256→HS256)
- Key confusion attacks
- PKCE bypass and weaknesses
- State parameter vulnerabilities
- Redirect URI manipulation
- Scope escalation attacks
- Authorization code injection
- Mix-up attacks

**WebAuthn/FIDO2 Vulnerabilities:**
- Virtual authenticator attacks
- Credential substitution and cloning
- Challenge reuse vulnerabilities
- Origin validation bypass
- Attestation bypass
- User verification bypass
- Counter manipulation
- Session confusion attacks

**Federation Vulnerabilities:**
- Confused deputy attacks
- Trust relationship misconfigurations
- IdP spoofing and impersonation
- Cross-domain assertion manipulation
- Provider confusion attacks
- Token reuse vulnerabilities


## Memory Notes

### Code and Documentation Standards

- **No emojis in code or documentation**: Keep it professional and parseable
- **Prefer editing existing files over creating new ones**: Avoid file proliferation
- **ALL output must use structured otelzap logging**: No fmt.Print/Printf/Println anywhere in codebase
  - CLI user output: Use `log.Info()` and `log.Infow()` with structured fields
  - Backend logging: Use `log.Debugw()`, `log.Warnw()`, `log.Errorw()` with component tags
  - Progress updates: Use periodic `log.Infow()` with progress_pct field
  - Interactive prompts: Log intent before/after using structured logging
- **ALL documentation must be inline in code files** (ENFORCED):
  - Strategic documentation: Header comments in relevant package/file
  - Tactical notes: Inline comments at exact location in code
  - Architecture decisions: Document in main package file (e.g., pkg/hera/hera.go)
  - Fix summaries: Inline with ADVERSARIAL REVIEW STATUS blocks
  - NEVER create standalone .md files for fix summaries, architecture docs, implementation status, or code review results
  - ONLY create standalone .md for: README.md, CLAUDE.md, CONTRIBUTING.md
  - When asked to document work, default to inline comments in code

### Priority System

When fixing issues, use this priority classification:

- **P0 (Critical)**: Data loss, corruption, silent failures, security vulnerabilities
  - Example: Unchecked errors in database operations, CSV writer failures
  - Fix immediately before release

- **P1 (High)**: Maintainability blockers, testing gaps, architectural issues
  - Example: 3,000+ line files, missing error returns, 0% test coverage
  - Fix before next major version

- **P2 (Medium)**: Code quality, technical debt, nice-to-haves
  - Example: TODO cleanup, improved naming, better documentation
  - Fix during normal development cycles

- **P3 (Low)**: Polish, minor improvements, future enhancements
  - Example: Code organization tweaks, style consistency
  - Fix when convenient

### Ethical Hacking Context

This tool is built BY ethical hackers FOR ethical hackers:

- Always assume use cases involve authorized testing only
- Include appropriate warnings about authorization requirements
- Design features to support evidence collection and responsible disclosure
- Consider impact on bug bounty researchers' reputation and credibility
- Remember that incomplete or incorrect results can cost researchers real money and trust

### Human-Centric Security

Following the "Cybersecurity. With humans." motto means:

- **Error handling must be transparent**: Silent failures damage user trust
- **Output must be actionable**: Security researchers need clear, reliable evidence
- **Reliability over speed**: Better to be slow and correct than fast and wrong
- **Sustainable code**: Maintainable code serves researchers long-term
- **Collaboration over automation**: Tool assists humans, doesn't replace judgment