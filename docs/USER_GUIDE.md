# Bug Bounty Optimization Guide - High-Value Vulnerability Hunting

This guide shows how to use shells optimized for finding high-value vulnerabilities in bug bounty programs.

## Quick Start - High-Value Scanning

```bash
# 1. Configure API keys (especially free CIRCL for passive DNS)
./shells config api-keys

# 2. Quick scan for critical vulnerabilities
./shells bounty example.com --quick

# 3. Deep scan focusing on authentication
./shells bounty example.com --auth --deep

# 4. Comprehensive scan with all modules
./scripts/bug-bounty-workflow.sh example.com
```

## High-Value Vulnerability Focus Areas

### 1. Authentication Bypass (Highest Value)
```bash
# Discover all authentication endpoints
./shells auth discover --target example.com

# Test for Golden SAML attacks
./shells auth test --target example.com --protocol saml

# Test JWT vulnerabilities
./shells auth test --target api.example.com --protocol jwt

# Find authentication bypass chains
./shells auth chain --target example.com
```

**What to look for:**
- SAML assertion manipulation
- JWT algorithm confusion (none, RS256→HS256)
- OAuth2 redirect_uri bypass
- Password reset poisoning
- 2FA bypass

### 2. API Security (Critical for Modern Apps)
```bash
# Discover API endpoints
./shells api discover --target example.com

# Test GraphQL specifically
./shells api test --target example.com/graphql --introspection

# Test REST API authorization
./shells api test --target api.example.com --auth-bypass
```

**What to look for:**
- GraphQL introspection enabled
- Missing authorization checks
- API key leakage
- Mass assignment vulnerabilities
- Rate limiting bypass

### 3. Business Logic (High Impact)
```bash
# Test payment flows
./shells logic test --target example.com --payment

# Test for race conditions
./shells logic test --target example.com --race-conditions

# Test for IDOR
./shells logic test --target example.com --idor
```

**What to look for:**
- Price manipulation
- Negative value attacks
- Race conditions in transactions
- Coupon/discount stacking
- Workflow bypass

### 4. Request Smuggling (Infrastructure Level)
```bash
# Detect smuggling vulnerabilities
./shells smuggle detect https://example.com

# Exploit for cache poisoning
./shells smuggle exploit https://example.com --cache-poison
```

**What to look for:**
- CL.TE desync
- TE.CL desync
- HTTP/2 smuggling
- Cache poisoning opportunities

### 5. SSRF (Cloud Era Critical)
```bash
# Test for SSRF in webhooks
./shells ssrf test --target example.com --webhooks

# Test URL parameters
./shells ssrf test --target example.com --url-params

# Cloud metadata extraction
./shells ssrf exploit --target example.com --cloud-metadata
```

**What to look for:**
- Webhook URLs
- Image processing endpoints
- PDF generators
- Import/export features
- URL preview functions

### 6. Access Control (Always Present)
```bash
# Test for IDOR vulnerabilities
./shells access test --target example.com --idor

# Test privilege escalation
./shells access test --target example.com --privilege-escalation

# UUID prediction attacks
./shells access test --target example.com --uuid-prediction
```

**What to look for:**
- Direct object references
- Missing authorization checks
- Predictable identifiers
- Role manipulation
- Cross-tenant access

## Smart Attack Surface Discovery

The tool prioritizes high-value endpoints automatically:

```bash
# Smart discovery with priority scoring
./shells discover example.com --smart-mode

# Focus on specific high-value patterns
./shells discover example.com --focus "api,auth,admin,payment"
```

### Priority Scoring System

| Pattern | Score | Reason |
|---------|-------|---------|
| */login, */auth* | 100 | Authentication bypass potential |
| */oauth*, */saml* | 100 | Federation attacks |
| */api/*, */graphql* | 90-95 | API authorization issues |
| */admin*, */dashboard* | 85 | Privilege escalation |
| */payment*, */checkout* | 85 | Financial impact |
| */upload* | 75 | RCE potential |
| */webhook*, */callback* | 70 | SSRF potential |

## Efficient Bug Bounty Workflow

### 1. Initial Recon (5-10 minutes)
```bash
# Quick discovery of high-value targets
./shells discover example.com --smart-mode --quick

# Focus on authentication first
./shells auth discover --target example.com
```

### 2. Prioritized Testing (30-60 minutes)
```bash
# Test highest value first
./shells bounty example.com --quick

# If time permits, go deeper
./shells bounty example.com --deep
```

### 3. Exploitation & PoC (15-30 minutes)
```bash
# Generate proof of concepts
./shells poc generate --findings critical.json

# Demonstrate impact
./shells exploit demo --safe-mode
```

### 4. Reporting
```bash
# Generate bug bounty report
./shells report generate --template bug-bounty --findings all.json
```

## Tips for Maximum Efficiency

### 1. Configure API Keys
Even free APIs like CIRCL greatly improve discovery:
```bash
./shells config api-keys
# Configure at minimum:
# - CIRCL (free passive DNS)
# - Shodan (limited free tier)
```

### 2. Use Parallel Scanning
```bash
# Run multiple scans in parallel
./shells bounty example.com --threads 20
```

### 3. Focus on Your Strengths
```bash
# If you're good at auth bugs
./shells bounty example.com --auth --deep

# If you prefer API testing
./shells bounty example.com --api --deep
```

### 4. Chain Vulnerabilities
```bash
# Look for attack chains
./shells chain find --target example.com --max-impact
```

### 5. Monitor for Changes
```bash
# Set up monitoring for new endpoints
./shells monitor example.com --notify-new-endpoints
```

## Integration with Bug Bounty Platforms

### Import Scope
```bash
# Import program scope
./shells scope import hackerone my-program
./shells scope import bugcrowd my-program
```

### Validate Findings
```bash
# Ensure findings are in scope
./shells scope validate --findings results.json
```

## Example: Full Bug Bounty Session

```bash
# 1. Import scope
./shells scope import hackerone example-program

# 2. Smart discovery
./shells discover example.com --smart-mode

# 3. Quick high-value scan
./shells bounty example.com --quick

# 4. Deep dive on interesting findings
./shells auth test --target login.example.com --all
./shells api test --target api.example.com/graphql --deep

# 5. Generate report
./shells report generate --findings all.json --format markdown

# 6. Submit to platform
./shells submit hackerone --report report.md --program example-program
```

## Performance Metrics

Typical scan times for optimized bug bounty hunting:

- Quick scan: 5-15 minutes
- Standard scan: 30-60 minutes  
- Deep scan: 2-4 hours
- Comprehensive scan: 6-12 hours

## Responsible Disclosure

Always:
1. Stay within scope
2. Use rate limiting
3. Don't cause damage
4. Report findings properly
5. Follow platform guidelines

## Getting Help

```bash
# View all bug bounty commands
./shells bounty --help

# Get examples for specific vulnerability class
./shells examples auth-bypass
./shells examples api-security
./shells examples business-logic
```