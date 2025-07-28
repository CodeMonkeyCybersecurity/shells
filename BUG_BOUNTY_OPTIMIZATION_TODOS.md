# Bug Bounty Optimization TODOs

## Critical Issues to Fix

### 1. Integration Issue (HIGH PRIORITY)
**Location**: `/opt/shells/cmd/root.go:71-73`
```go
// FIXME: Bug bounty workflow not being called - runMainDiscovery should use optimized workflow
// TODO: Add flag to skip discovery and go straight to vuln testing (--quick-scan)
```

### 2. Reduce Discovery Noise
**Location**: `/opt/shells/cmd/root.go:2217-2223`
```go
// FIXME: Output format - reduce JSON logs, use clean formatted output
// TODO: Set log level to WARN for bug bounty mode to reduce noise
```

**Location**: `/opt/shells/internal/discovery/types.go:186-201`
```go
// TODO: Add BugBountyConfig() for optimized settings
// FIXME: These defaults are too slow for bug bounty hunting
Timeout: 30 * time.Minute, // FIXME: Way too long - max 30 seconds
EnableDNS: true,           // TODO: Make optional - low value
EnableCertLog: true,       // FIXME: Disable by default - too slow
EnableSearch: true,        // FIXME: Disable - not needed for direct targets
```

### 3. Time-Boxing Operations
**Location**: `/opt/shells/cmd/root.go:2233-2240`
```go
// TODO: Time-box discovery to max 30 seconds
discoveryTimeout := 30 * time.Second
discoveryCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
```

**Location**: `/opt/shells/pkg/discovery/certlogs/ctlog.go:59-61`
```go
// FIXME: 30 seconds is way too long for bug bounty
// TODO: Reduce to 5 seconds max
Timeout: 30 * time.Second,
```

### 4. Mail-Specific Vulnerability Tests
**Location**: `/opt/shells/cmd/scanner_executor.go:58-65`
```go
// TODO: For mail servers, add these quick tests:
// - Default credentials (admin:admin, postmaster:postmaster)
// - Open relay
// - Webmail XSS
// - Mail header injection
```

**Location**: `/opt/shells/cmd/vuln_testing.go:64-71`
```go
// TODO: Implement these tests:
// - SMTP AUTH bypass
// - Webmail XSS/SQLi
// - Mail header injection
// - Open relay
// - Default credentials
```

### 5. Output Format Issues
**Location**: `/opt/shells/cmd/root.go:130-139`
```go
// TODO: Default log level should be "warn" for bug bounty mode
// FIXME: JSON logs are too noisy - default to console for bug bounty
// TODO: Add bug bounty specific flags:
// --quick: Quick scan mode - skip discovery
// --quiet: Quiet mode - only show vulnerabilities
// --timeout: Maximum scan time
```

**Location**: `/opt/shells/pkg/discovery/passivedns/client.go:159-163`
```go
// FIXME: Change to Debug level - too noisy for bug bounty
p.logger.Debug("Passive DNS query completed",
```

## Implementation Priority

### Phase 1: Quick Fixes (1-2 hours)
1. Change default log levels to reduce noise
2. Disable slow discovery modules by default
3. Add time-boxing to all operations
4. Fix the integration so bug bounty workflow actually runs

### Phase 2: Vulnerability Testing (4-6 hours)
1. Implement mail server vulnerability tests
2. Add API security tests (GraphQL, JWT)
3. Implement business logic tests
4. Add request smuggling detection
5. Implement SSRF tests

### Phase 3: Output Improvements (2-3 hours)
1. Replace JSON logs with clean formatted output
2. Add progress indicators for each test phase
3. Show vulnerabilities in clear format:
   ```
   [CRITICAL] SQL Injection in /login (parameter: username)
   [HIGH] XSS in /search (parameter: q)
   ```

## Value-for-Time Optimizations

### Skip These for Bug Bounty:
- Certificate timeline analysis
- Passive DNS (unless good APIs available)
- Azure blob enumeration
- Extensive web crawling
- Recursive discovery
- WHOIS correlation (unless targeting organization)

### Focus On These High-Value Tests:
1. **Authentication** (30% of bug bounties)
   - SAML golden tickets
   - JWT algorithm confusion
   - OAuth redirect bypass

2. **API Security** (25% of bug bounties)
   - GraphQL introspection
   - Authorization bypass
   - Mass assignment

3. **Business Logic** (20% of bug bounties)
   - IDOR
   - Payment manipulation
   - Race conditions

4. **Infrastructure** (15% of bug bounties)
   - Request smuggling
   - SSRF
   - Open redirects

5. **Access Control** (10% of bug bounties)
   - Privilege escalation
   - Cross-tenant access

## Testing the Optimizations

After implementing these changes:
```bash
# Should complete in <1 minute with findings
shells mail.cybermonkey.sh

# Expected output:
🎯 High-Value Bug Bounty Scanner
=== Phase 1: Smart Attack Surface Discovery (30s max) ===
✓ Found mail server with 8 open ports
=== Phase 2: Vulnerability Testing ===
[1/6] Testing Authentication... ✓ 1 vulnerability
[2/6] Testing Mail Services... ✓ 2 vulnerabilities
=== Phase 3: Results ===
[CRITICAL] Default admin credentials at /webmail/admin
[HIGH] Open relay on SMTP port 25
[MEDIUM] Missing SPF records
```