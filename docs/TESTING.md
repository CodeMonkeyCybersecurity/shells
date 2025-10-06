# Testing Guide - IPv6 Fix Verification

**Purpose**: Verify that IPv6 address format bugs are fixed and the tool works with both IPv4 and IPv6 targets.

---

## Quick Verification (2 minutes)

### 1. Build Check
```bash
# Ensure clean build
make clean
make build

# Verify go vet passes
go vet ./...
# Should complete with no errors 
```

### 2. Basic Functionality Test
```bash
# Test version command (quick sanity check)
./shells version

# Test help (verify CLI works)
./shells --help
```

---

## IPv6 Testing (5-10 minutes)

### Test 1: Port Scanning with IPv6

**Public IPv6 DNS Servers** (safe to test):
```bash
# Google Public DNS (IPv6)
./shells scan 2001:4860:4860::8888 --ports 80,443,53

# Cloudflare DNS (IPv6)
./shells scan 2606:4700:4700::1111 --ports 80,443,53
```

**Expected Result**:
-  No connection errors related to address format
-  Port scan completes (may show ports as closed, that's fine)
- ❌ Should NOT see: "invalid address" or "too many colons" errors

### Test 2: SMTP Testing with IPv6

```bash
# Test SMTP discovery (if you have an IPv6 mail server)
./shells mail analyze example.com

# Manual SMTP client test (requires test environment)
# See internal/vulntest/smtp_client_test.go for examples
```

### Test 3: Authentication Discovery with IPv6

```bash
# Test auth endpoint discovery with IPv6
./shells auth discover --target 2001:4860:4860::8888
```

**Expected Result**:
-  Scanner attempts connections without address format errors
-  Handles IPv6 addresses correctly in all network operations

---

## IPv4 Regression Testing (3 minutes)

**Ensure IPv4 still works**:
```bash
# Standard IPv4 testing
./shells scan 8.8.8.8 --ports 80,443,53

# Domain testing (resolves to IPv4)
./shells scan google.com --ports 80,443

# IPv4 CIDR range
./shells scan 192.168.1.0/24 --quick
```

**Expected Result**:
-  All IPv4 operations work as before
-  No regressions introduced

---

## Mixed Environment Testing (5 minutes)

### Test Dual-Stack Hosts

```bash
# Scan a dual-stack domain (has both IPv4 and IPv6)
./shells scan google.com --verbose

# Should handle both address families correctly
```

### Test Discovery Pipeline

```bash
# Full discovery on a modern target
./shells discover cloudflare.com --smart-mode

# Should discover and test both IPv4 and IPv6 endpoints
```

---

## Automated Test Suite (2 minutes)

```bash
# Run existing test suite
make test

# Run with race detection (optional, takes longer)
make test-race

# Run specific package tests
go test ./pkg/discovery/portscan/... -v
go test ./internal/vulntest/... -v
go test ./pkg/auth/discovery/... -v
```

**Expected Result**:
-  All tests pass
-  No panics or address format errors

---

## Error Case Testing (3 minutes)

### Test Invalid Inputs

```bash
# Invalid IPv6 address (should error gracefully)
./shells scan "2001:invalid::address" --ports 80

# Malformed address
./shells scan "[2001:db8::1" --ports 80

# Empty address
./shells scan "" --ports 80
```

**Expected Result**:
-  Proper error messages (not panics)
-  Graceful handling of invalid input

---

## Bug Bounty Workflow Testing (10 minutes)

### End-to-End IPv6 Bug Bounty Test

```bash
# 1. Test bug bounty mode with IPv6 target
./shells bounty 2606:4700:4700::1111 --quick

# 2. Test comprehensive scan
./shells bounty example-ipv6-site.com --deep

# 3. Check results
./shells results query --severity critical
./shells results stats
```

**Expected Result**:
-  Full bug bounty workflow completes
-  No network connection errors
-  Results properly stored and queryable

---

## Performance Testing (Optional, 15 minutes)

### Benchmark IPv6 vs IPv4 Performance

```bash
# IPv4 baseline
time ./shells scan 8.8.8.8 --ports 1-1000

# IPv6 comparison
time ./shells scan 2001:4860:4860::8888 --ports 1-1000

# Should be comparable performance
```

---

## Known Limitations to Verify

### 1. IPv6 Literal in URLs
```bash
# Test HTTP scanning with IPv6 (should use brackets)
curl http://[2606:4700:4700::1111]:80
# Verify our tool does the same internally
```

### 2. DNS Resolution
```bash
# Test that AAAA record discovery works
./shells discover example.com --include-ipv6
```

---

## Rollback Plan

If IPv6 fixes cause issues:

```bash
# Revert specific file
git checkout HEAD^ pkg/discovery/portscan/scanner.go

# Or revert all IPv6 fixes
git revert <commit-hash>
```

**Files to Revert** (if needed):
1. internal/vulntest/smtp_client.go
2. pkg/discovery/portscan/scanner.go
3. pkg/discovery/mail_analyzer.go
4. pkg/auth/discovery/portscanner.go

---

## Success Criteria 

The IPv6 fixes are verified successful if:

1.  `go vet ./...` passes with no warnings
2.  `make test` passes all tests
3.  IPv6 addresses don't cause connection errors
4.  IPv4 functionality unchanged (no regression)
5.  Port scanning works on public IPv6 DNS servers
6.  Bug bounty workflow completes end-to-end
7.  No panics or crashes on edge cases

---

## Reporting Issues

If you find IPv6-related bugs:

1. **Check go vet output**:
   ```bash
   go vet ./... 2>&1 | grep -i ipv6
   ```

2. **Run with verbose logging**:
   ```bash
   ./shells scan <target> --verbose --log-level debug
   ```

3. **Capture stack trace** (if panic):
   ```bash
   GOTRACEBACK=all ./shells scan <target>
   ```

4. **Report**: Include the exact command, error output, and target type (IPv4/IPv6/domain)

---

## Additional Notes

- **Safe IPv6 Test Targets**:
  - 2001:4860:4860::8888 (Google DNS)
  - 2606:4700:4700::1111 (Cloudflare DNS)
  - 2001:4860:4860::8844 (Google DNS alternate)

- **Do NOT test**:
  - Private IPv6 ranges without permission
  - Production systems without authorization
  - Rate-limit sensitive services

- **Best Practice**:
  - Always use `--rate-limit` flag for production testing
  - Respect target's terms of service
  - Stay within bug bounty program scope
