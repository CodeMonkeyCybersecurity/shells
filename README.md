# Shells - Intelligent Bug Bounty Automation

**By Code Monkey Cybersecurity (ABN 77 177 673 061)**
**Motto**: "Cybersecurity. With humans."

Shells is a comprehensive security scanning platform designed for bug bounty hunters and security researchers. Point it at a target (company name, domain, IP, or email) and it automatically discovers assets, tests for vulnerabilities, and generates actionable findings.

**Current Status**: 1.0.0-beta - Production ready with known limitations

## Quick Start

**Super Easy - One Command Installation:**

```bash
# Clone and run install script (handles everything automatically)
git clone https://github.com/CodeMonkeyCybersecurity/shells
cd shells
./install.sh

# Start web dashboard
shells serve --port 8080

# Open browser to http://localhost:8080 and start scanning!
```

**What install.sh does automatically:**
- ✅ Installs/updates Go 1.24.4
- ✅ Installs PostgreSQL and creates database
- ✅ Builds shells binary
- ✅ Sets up Python workers (GraphCrawler, IDORD)
- ✅ Configures everything - just run and go!

**Run scans:**

```bash
# Full automated workflow
shells example.com

# Or specify target type
shells "Acme Corporation"    # Discover company assets
shells admin@example.com     # Discover from email
shells 192.168.1.0/24        # Scan IP range
```

## Features

### Automated Asset Discovery
- **From company name**: Certificate transparency logs, WHOIS, DNS enumeration
- **From domain**: Subdomain discovery, related domains, tech stack fingerprinting
- **From IP/range**: Network scanning, service discovery, reverse DNS
- **From email**: Domain extraction, mail server analysis

### Vulnerability Testing
- **Authentication Security**: SAML (Golden SAML, XSW), OAuth2/OIDC (JWT attacks, PKCE bypass), WebAuthn/FIDO2
- **SCIM Vulnerabilities**: Unauthorized provisioning, filter injection, privilege escalation
- **HTTP Request Smuggling**: CL.TE, TE.CL, TE.TE desync attacks
- **Business Logic Testing**: Password reset flows, payment processing
- **Infrastructure**: SSL/TLS analysis, port scanning

### Results & Reporting
- **PostgreSQL database**: Production-ready storage with full ACID compliance
- **Web dashboard**: Real-time scan progress and findings viewer at `http://localhost:8080`
- **Export formats**: JSON, CSV, HTML
- **Query & filter**: By severity, tool, target, date range
- **Statistics**: Aggregate findings, trend analysis
- **Auto-refresh**: Dashboard updates every 5 seconds

## Installation

### Automated Installation (Zero Configuration)

**Just run `./install.sh` - it handles EVERYTHING:**

```bash
# Clone and install (one command does it all!)
git clone https://github.com/CodeMonkeyCybersecurity/shells
cd shells
./install.sh

# That's it! Now start scanning:
shells serve --port 8080
```

**What install.sh does automatically:**
1. ✅ Detects your platform (Linux/macOS)
2. ✅ Updates system packages (if needed)
3. ✅ Installs Go 1.24.4
4. ✅ **Installs PostgreSQL** (brew on macOS, apt/dnf on Linux)
5. ✅ **Creates database and user** (`shells` database with `shells` user)
6. ✅ **Configures connection string** in `.shells.yaml`
7. ✅ Builds the `shells` binary
8. ✅ Installs to `/usr/local/bin/shells`
9. ✅ Sets up Python workers (GraphCrawler, IDORD)
10. ✅ Creates config/log/secret directories

**No manual PostgreSQL setup needed!** The script detects if you have Docker and offers to use a container, or installs PostgreSQL natively. Everything just works.

**After installation:**
```bash
# Start the web dashboard (workers auto-start)
shells serve --port 8080

# Open http://localhost:8080 in your browser

# Or run a scan directly
shells example.com
```

### Manual Installation (Advanced)

```bash
# Clone repository
git clone https://github.com/CodeMonkeyCybersecurity/shells
cd shells

# Build binary
go build -o shells

# Optional: Install to PATH
sudo cp shells /usr/local/bin/
sudo chmod 755 /usr/local/bin/shells
```

### Requirements
- **Go**: 1.21 or higher (automatically installed by install.sh)
- **PostgreSQL**: 15 or higher (required for database storage)
- **Python 3.8+**: Optional, for GraphCrawler and IDORD workers
- **Docker**: Optional, for containerized deployment
- **Git**: For cloning and updates

### Docker Deployment (Production)

For production deployments, use Docker Compose to run shells with all dependencies in a single network:

```bash
cd deployments/docker

# Start full stack (PostgreSQL + Redis + OTEL + Shells API + Workers)
docker-compose up -d

# View logs
docker-compose logs -f shells-api

# Access web dashboard at http://localhost:8080
```

**Architecture**:
- `shells-api`: Main API server with web dashboard (port 8080)
- `webscan-worker`: 3 worker instances for distributed scanning
- `postgres`: PostgreSQL database (single source of truth)
- `redis`: Job queue for worker coordination
- `otel-collector`: OpenTelemetry metrics collection
- `nmap`: Network scanning container
- `zap`: OWASP ZAP proxy container

**Key Benefits**:
- ✅ **Single database**: All containers share the same PostgreSQL instance
- ✅ **No data duplication**: Workers and API use the same dataset
- ✅ **Scalable**: Increase worker replicas in docker-compose.yml
- ✅ **Persistent storage**: Database and Redis data survive container restarts
- ✅ **Network isolation**: All containers in isolated Docker network

```bash
# Scale workers
docker-compose up -d --scale webscan-worker=10

# Stop all services
docker-compose down

# Stop and remove data volumes
docker-compose down -v
```

## Usage

### Point-and-Click Mode

The main command runs the full orchestrated pipeline:

```bash
# Full automated workflow: Discovery → Prioritization → Testing → Reporting
./shells example.com
```

### Targeted Commands

```bash
# Asset discovery only
./shells discover example.com

# Authentication testing
./shells auth discover --target https://example.com
./shells auth test --target https://example.com --protocol saml
./shells auth chain --target https://example.com  # Find attack chains

# SCIM security testing
./shells scim discover https://example.com
./shells scim test https://example.com/scim/v2 --test-all

# HTTP request smuggling
./shells smuggle detect https://example.com
./shells smuggle exploit https://example.com --technique cl.te

# Results querying
./shells results query --severity critical
./shells results stats
./shells results export scan-12345 --format json

# Bug bounty platform integration
./shells platform programs --platform hackerone
./shells platform submit <finding-id> --platform bugcrowd --program my-program
./shells platform auto-submit --severity CRITICAL

# Self-management
./shells self update                    # Update to latest version
./shells self update --branch develop   # Update from specific branch
```

### Python Worker Services (GraphQL & IDOR Scanning)

Shells integrates specialized Python tools for GraphQL and IDOR vulnerability detection:

```bash
# One-time setup (clones GraphCrawler & IDORD, creates venv)
shells workers setup

# Start worker service
shells workers start

# Or start API server with workers auto-started
shells serve  # Workers start automatically

# Check worker health
shells workers status

# Stop workers
shells workers stop
```

**Integrated Tools:**
- **GraphCrawler** ([gsmith257-cyber/GraphCrawler](https://github.com/gsmith257-cyber/GraphCrawler))
  - GraphQL endpoint discovery
  - Schema introspection
  - Mutation detection
  - Authorization testing

- **IDORD** ([AyemunHossain/IDORD](https://github.com/AyemunHossain/IDORD))
  - Automated IDOR vulnerability scanning
  - Multi-user authorization testing
  - Smart ID fuzzing (numeric, UUID, alphanumeric)
  - Authenticated testing support

**Worker Architecture:**
- FastAPI service wraps Python tools
- REST API for job submission and status
- Background task execution with polling
- Automatic integration when running `shells serve`

### Configuration

Create `.shells.yaml` in your home directory:

```yaml
logger:
  level: info
  format: json

database:
  driver: sqlite3
  dsn: "~/.shells/shells.db"

scanning:
  rate_limit: 10  # requests per second
  timeout: 30s
  max_depth: 3    # asset discovery depth
```

## Architecture

### Directory Structure
- `/cmd/` - CLI commands (Cobra)
- `/internal/` - Internal packages
  - `config/` - Configuration management
  - `database/` - SQLite storage layer
  - `discovery/` - Asset discovery modules
  - `orchestrator/` - Bug bounty workflow engine
  - `logger/` - Structured logging (otelzap)
- `/pkg/` - Public packages
  - `auth/` - Authentication testing (SAML, OAuth2, WebAuthn)
  - `scim/` - SCIM vulnerability testing
  - `smuggling/` - HTTP request smuggling detection
  - `discovery/` - Asset discovery utilities

### Key Technologies
- **Go**: Performance and reliability
- **SQLite**: Embedded database (no external dependencies)
- **Cobra**: CLI framework
- **OpenTelemetry**: Observability and tracing
- **Context**: Proper cancellation and timeouts

## Testing

```bash
# Run all tests
make test

# Run specific package tests
go test ./pkg/auth/...
go test ./pkg/scim/...

# With coverage
go test -cover ./...

# Verify build
make check  # Runs fmt, vet, and test
```

See [docs/TESTING.md](docs/TESTING.md) for comprehensive testing guide including IPv6 verification.

## Development

### Adding New Features

1. **New Scanner Command**:
   - Add command in `/cmd/`
   - Follow existing patterns (see `cmd/auth.go`)
   - Register in `init()` function
   - Add tests

2. **New Scanner Plugin**:
   - Create directory in `/internal/plugins/`
   - Implement plugin interface
   - Add configuration options
   - Register in worker system

See [CLAUDE.md](CLAUDE.md) for detailed development guidance including:
- Collaboration principles
- Code standards
- Priority system (P0-P3)
- Testing guidelines

### Build Commands

```bash
make deps          # Download dependencies
make build         # Build binary
make dev           # Build with race detection
make test          # Run tests
make check         # Run fmt, vet, test (pre-commit)
make fmt           # Format code
make vet           # Check for issues
make clean         # Remove binary
```

## Known Limitations (Beta)

### In Development
- **Mail Server Testing**: Planned for v1.1.0
- **Advanced API Testing**: Planned for v1.1.0
- **Test Coverage**: Currently ~8%, targeting 50% for v1.2.0

### Code Organization
- `cmd/root.go` is 3,169 lines (refactoring in progress)
- Some TODO markers in codebase
- See [CLAUDE.md](CLAUDE.md) for complete technical debt inventory

### Performance
- Optimized for thoroughness over speed
- Rate limiting prevents target overload
- Parallel scanning of discovered assets

## Security Considerations

This tool is for **authorized security testing only**:

- Always obtain explicit permission before scanning
- Respect rate limits and terms of service
- Follow responsible disclosure practices
- Never use against production systems without authorization
- Verify scope before running automated scans

### Built-In Protections
- No hardcoded credentials
- SQL injection protection (parameterized queries)
- SSRF protection in HTTP client
- Context cancellation prevents hangs
- Graceful error handling

## Bug Bounty Workflow

See [docs/BUG-BOUNTY-GUIDE.md](docs/BUG-BOUNTY-GUIDE.md) for complete workflow guide.

**Typical Usage**:
1. Research target scope
2. Run discovery: `./shells discover target.com`
3. Review discovered assets
4. Run full scan: `./shells target.com`
5. Query findings: `./shells results query --severity high`
6. Export evidence: `./shells results export scan-id --format json`
7. Verify findings manually
8. Submit responsible disclosure

## Contributing

We welcome contributions! Please:

1. Read [CLAUDE.md](CLAUDE.md) for development guidelines
2. Follow existing code patterns
3. Add tests for new functionality
4. Run `make check` before committing
5. Write clear commit messages
6. Focus on sustainable, maintainable solutions

**Philosophy**: We prioritize human-centric security, evidence-based approaches, and collaboration. See [CLAUDE.md](CLAUDE.md) for our working principles.

## Documentation

- [CLAUDE.md](CLAUDE.md) - Development guide and collaboration principles
- [docs/BUG-BOUNTY-GUIDE.md](docs/BUG-BOUNTY-GUIDE.md) - Bug bounty workflow
- [docs/TESTING.md](docs/TESTING.md) - Testing and verification guide

## Roadmap
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

## License

[Add license information]

## Support

- **Issues**: [GitHub Issues](https://github.com/CodeMonkeyCybersecurity/shells/issues)
- **Documentation**: See `/docs` directory
- **Contact**: Code Monkey Cybersecurity

---

**Remember**: "Cybersecurity. With humans." - This tool assists security researchers, it doesn't replace human judgment and expertise.
