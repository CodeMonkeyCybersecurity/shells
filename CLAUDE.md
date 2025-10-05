# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**shells** is a security scanning tool built in Go by Code Monkey Cybersecurity (ABN 77 177 673 061).

**Motto**: "Cybersecurity. With humans."

### Philosphy
- **Human centric**: , actionable output, addresses barriers to entry, encourage end-user ducation and self-efficacy, feminist (for example, informed consent), safe effective high-quality
- **Evidence based**: accepts falliblism, error correction, value for time, value for money
- **Sustainable innovation**: Maintainable code, comprehensive documentation, iterative improvement, response ready, incorporates recent research and best practice
- **Collaboration and listening**: Built by ethical hackers for ethical hackers, transparent decision making, ownership accountability responsibility, open source

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

**shells** supports intelligent asset discovery where users can run `shells [target]` and the tool automatically discovers and tests all associated assets. The target can be:

- **Company name**: "Acme Corporation"
- **Email address**: "admin@acme.com" 
- **Domain**: "acme.com"
- **IP address**: "192.168.1.1"
- **IP range**: "192.168.1.0/24"

### Implementation Requirements

When implementing the main discovery command, the tool should:

1. **Parse and classify the input target**:
   - Detect if input is company name, email, domain, IP, or IP range
   - Use appropriate discovery techniques based on input type

2. **Asset Discovery Pipeline**:
   - **From company name**: Use search engines, certificate transparency, WHOIS, DNS
   - **From email**: Extract domain, perform DNS enumeration, find related domains
   - **From domain**: DNS enumeration, subdomain discovery, related domain finding
   - **From IP**: Reverse DNS, network scanning, neighboring IP discovery
   - **From IP range**: Network enumeration, service discovery

3. **Spider out to find related assets**:
   - DNS enumeration (subdomains, related domains)
   - Certificate transparency logs
   - Search engine dorking
   - WHOIS data analysis
   - Network range discovery
   - Technology stack fingerprinting

4. **Apply all available testing functionality**:
   - Run all scanner plugins automatically
   - Apply business logic testing framework
   - Execute authentication testing (OAuth2, SAML, WebAuthn)
   - Perform infrastructure scanning (Nmap, Nuclei, SSL)
   - Test for HTTP request smuggling and SCIM vulnerabilities
   - Apply favicon analysis and AWS/cloud asset discovery

5. **Intelligent prioritization**:
   - Prioritize high-value targets (login pages, admin panels, APIs)
   - Focus on authentication endpoints for business logic testing
   - Identify and test payment/e-commerce functionality
   - Look for privilege escalation opportunities

6. **Comprehensive reporting**:
   - Aggregate all findings across discovered assets
   - Show asset relationships and discovery chain
   - Provide actionable remediation guidance
   - Generate business impact assessments

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

## Debugging Tips

- Use structured logging with otelzap (opentelemetry and zap logging) traces for distributed tracing
- Enable debug logging by default
- Use OpenTelemetry 
- Check worker logs for scanning issues
- Monitor Redis queue for job status

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
- **Documentation files only for strategic changes**: Don't create docs for every small change
- **Inline comments for tactical notes**: Documentation should live at the exact place in code where it's needed, not in separate files
- **Inline notation is a strong preference**: Keeps context close to implementation

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