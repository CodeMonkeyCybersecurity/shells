# Complete Wiring & Integration Plan: Making Shells Fully Functional

**Date**: 2025-10-23
**Goal**: Wire all implemented features into the orchestrator and expose them to users
**Status**: ~75% architecturally complete, ~50% user-accessible

---

## Executive Summary

The shells codebase has excellent architecture with many powerful features already implemented. However, **critical features are disconnected**: scanners exist but aren't initialized, discovery finds assets but doesn't display them, database stores rich data but no commands query it, and the HERA phishing detection API has 5 schema mismatches that break it completely.

**This plan provides a systematic approach to wire everything together in priority order.**

---

## Phase 1: Critical Database Fixes (1 day)

### P0-1: Fix HERA Database Schema Mismatches

**Impact**: HERA browser extension is completely broken
**Files**:
- `/Users/henry/Dev/shells/internal/api/hera.go:1-150`
- `/Users/henry/Dev/shells/migrations/*.sql`

**Problems**:
1. **WHOIS Cache Schema**: Code queries `registration_date, registrar, age_days, raw_data` but schema only has `domain, whois_data, created_at, expires_at`
2. **Threat Intel Schema**: Code expects `source, verdict, score, details` but schema only has `domain, malicious, sources, last_checked, expires_at`
3. **PostgreSQL vs SQLite**: Uses `NOW()` function (PostgreSQL only) when default is SQLite
4. **Placeholder Mismatch**: Uses `$1, $2` (PostgreSQL) instead of `?` (SQLite)
5. **Stats Table**: Columns don't match queries

**Solution**:
```sql
-- 1. Add missing columns to hera_whois_cache
ALTER TABLE hera_whois_cache ADD COLUMN registration_date TIMESTAMP;
ALTER TABLE hera_whois_cache ADD COLUMN registrar TEXT;
ALTER TABLE hera_whois_cache ADD COLUMN age_days INTEGER;
ALTER TABLE hera_whois_cache ADD COLUMN raw_data TEXT;

-- 2. Add missing columns to hera_threat_intel
ALTER TABLE hera_threat_intel ADD COLUMN source TEXT;
ALTER TABLE hera_threat_intel ADD COLUMN verdict TEXT;
ALTER TABLE hera_threat_intel ADD COLUMN score REAL;
ALTER TABLE hera_threat_intel ADD COLUMN details TEXT;

-- 3. Fix stats table structure (details in hera.go:1-150)
```

**Code Changes**:
```go
// Create database abstraction layer for cross-DB compatibility
type DBAdapter interface {
    Now() string              // Returns "NOW()" for PostgreSQL, "datetime('now')" for SQLite
    Placeholder(n int) string // Returns "$n" for PostgreSQL, "?" for SQLite
}

// Update all queries to use adapter
```

**Estimated Time**: 4-6 hours
**Validation**: Run HERA browser extension against shells server, verify domain analysis works

---

### P0-2: Fix Organization Footprinting Silent Failures

**Impact**: Phase 0 discovers zero related domains
**Files**:
- `/Users/henry/Dev/shells/pkg/correlation/organization_correlator.go`
- `/Users/henry/Dev/shells/internal/orchestrator/bounty_engine.go:529-536`

**Problems**:
1. `FindOrganizationAssets()` fails but errors are swallowed with warning
2. WHOIS client may be failing to extract domains
3. Cert transparency client not hitting crt.sh correctly
4. No detailed error logging to diagnose root cause

**Solution**:
```go
// 1. Add verbose error context
org, err := e.orgCorrelator.FindOrganizationAssets(ctx, target)
if err != nil {
    // Instead of:
    dbLogger.Warnw("Organization footprinting failed, proceeding with single target")

    // Do:
    dbLogger.Errorw("CRITICAL: Organization footprinting failed",
        "error", err,
        "error_type", fmt.Sprintf("%T", err),
        "target", target,
        "whois_enabled", e.config.EnableWHOISAnalysis,
        "cert_enabled", e.config.EnableCertTransparency,
        "asn_enabled", true,
    )
    // Log detailed breakdown of which client failed
    if whoisErr := testWhoisClient(target); whoisErr != nil {
        dbLogger.Errorw("WHOIS client test failed", "error", whoisErr)
    }
    if certErr := testCertClient(target); certErr != nil {
        dbLogger.Errorw("Cert transparency client test failed", "error", certErr)
    }
}

// 2. Add unit tests for each client with mocks
// 3. Add integration test with real cybermonkey.net.au
// 4. Document expected behavior in test comments
```

**Estimated Time**: 3-4 hours
**Validation**: Run against `cybermonkey.net.au`, should discover related Code Monkey domains

---

## Phase 2: Display Discovery Results (1 day)

### P0-3: Display Organization Footprinting Results

**Impact**: User has no visibility into discovered organization assets
**Files**: `/Users/henry/Dev/shells/cmd/orchestrator_main.go:172-257`

**Solution**:
```go
// Add between Phase 0 and Phase 1 in cmd/orchestrator_main.go

func displayFootprintingResults(org *correlation.Organization) {
    if org == nil || org.Name == "" {
        return
    }

    fmt.Println()
    color.Cyan("═══ Phase 0: Organization Footprinting ═══")

    // Organization info
    fmt.Printf("  Organization: %s\n", color.GreenString(org.Name))
    if org.Confidence > 0 {
        fmt.Printf("  Confidence: %.1f%%\n", org.Confidence * 100)
    }

    // Related domains
    if len(org.Domains) > 0 {
        fmt.Printf("\n  ✓ Found %d related domains:\n", len(org.Domains))
        for i, domain := range org.Domains {
            if i < 10 { // Show first 10
                fmt.Printf("    • %s\n", domain)
            }
        }
        if len(org.Domains) > 10 {
            fmt.Printf("    ... and %d more\n", len(org.Domains) - 10)
        }
    }

    // IP ranges
    if len(org.IPRanges) > 0 {
        fmt.Printf("\n  ✓ Found %d IP ranges:\n", len(org.IPRanges))
        for _, ipRange := range org.IPRanges {
            fmt.Printf("    • %s\n", ipRange)
        }
    }

    // ASNs
    if len(org.ASNs) > 0 {
        fmt.Printf("\n  ✓ Found %d ASNs:\n", len(org.ASNs))
        for _, asn := range org.ASNs {
            fmt.Printf("    • AS%d\n", asn)
        }
    }

    // Certificates
    if len(org.Certificates) > 0 {
        fmt.Printf("\n  ✓ Found %d SSL certificates\n", len(org.Certificates))
    }

    // Sources
    if len(org.Sources) > 0 {
        fmt.Printf("\n  Sources: %s\n", strings.Join(org.Sources, ", "))
    }

    fmt.Println()
}

// Call it in bounty_engine.go after Phase 0:
if org != nil {
    displayFootprintingResults(org)
}
```

**Estimated Time**: 2 hours

---

### P0-4: Display Asset Discovery Results

**Impact**: User sees "1 asset discovered" but not WHAT was discovered
**Files**: `/Users/henry/Dev/shells/cmd/orchestrator_main.go:172-257`

**Solution**:
```go
func displayDiscoveryResults(session *discovery.DiscoverySession, assets []*discovery.Asset) {
    fmt.Println()
    color.Cyan("═══ Phase 1: Asset Discovery ═══")

    // Group assets by type
    assetsByType := make(map[discovery.AssetType][]*discovery.Asset)
    for _, asset := range assets {
        assetsByType[asset.Type] = append(assetsByType[asset.Type], asset)
    }

    // Display subdomains
    if subdomains := assetsByType[discovery.AssetTypeSubdomain]; len(subdomains) > 0 {
        fmt.Printf("\n  ✓ Discovered %d subdomains:\n", len(subdomains))
        for i, asset := range subdomains {
            if i < 15 { // Show first 15
                priority := ""
                if discovery.IsHighValueAsset(asset) {
                    priority = color.RedString(" [HIGH VALUE]")
                }
                fmt.Printf("    • %s%s\n", asset.Value, priority)
            }
        }
        if len(subdomains) > 15 {
            fmt.Printf("    ... and %d more\n", len(subdomains) - 15)
        }
    }

    // Display IPs with open ports
    if ips := assetsByType[discovery.AssetTypeIP]; len(ips) > 0 {
        fmt.Printf("\n  ✓ Found %d IP addresses:\n", len(ips))
        for _, asset := range ips {
            ports := ""
            if p, ok := asset.Metadata["open_ports"]; ok {
                ports = fmt.Sprintf(" - Ports: %s", p)
            }
            fmt.Printf("    • %s%s\n", asset.Value, ports)
        }
    }

    // Display services with versions
    if services := assetsByType[discovery.AssetTypeService]; len(services) > 0 {
        fmt.Printf("\n  ✓ Found %d services:\n", len(services))
        for _, asset := range services {
            version := ""
            if v, ok := asset.Metadata["version"]; ok {
                version = fmt.Sprintf(" (%s)", v)
            }
            fmt.Printf("    • %s:%s%s%s\n",
                asset.IP,
                asset.Metadata["port"],
                asset.Metadata["service_name"],
                version,
            )
        }
    }

    // Display technologies
    techSet := make(map[string]bool)
    for _, asset := range assets {
        for _, tech := range asset.Technology {
            techSet[tech] = true
        }
    }
    if len(techSet) > 0 {
        techs := make([]string, 0, len(techSet))
        for tech := range techSet {
            techs = append(techs, tech)
        }
        fmt.Printf("\n  ✓ Technologies detected: %s\n", strings.Join(techs, ", "))
    }

    // High-value asset summary
    if session != nil && session.HighValueAssets > 0 {
        fmt.Printf("\n  %s Found %d high-value assets\n",
            color.RedString("⚠️"),
            session.HighValueAssets,
        )
    }

    fmt.Println()
}

// Modify executeDiscoveryPhase to return session:
func (e *BugBountyEngine) executeDiscoveryPhase(ctx context.Context, target string, tracker *progress.Tracker, logger *logger.Logger) ([]*discovery.Asset, *discovery.DiscoverySession, error) {
    session, err := e.discoveryEngine.StartDiscovery(target)
    // ... wait for completion
    return assets, session, nil
}
```

**Estimated Time**: 3 hours

---

### P0-5: Display Vulnerability Findings Summary

**Impact**: User sees "0 findings" but not what was tested
**Files**: `/Users/henry/Dev/shells/cmd/orchestrator_main.go:214-257`

**Current**:
```
Total Findings: 0

ℹ No high-severity vulnerabilities found
```

**Better**:
```
═══ Phase 3: Vulnerability Testing ═══

  ✓ Authentication Testing:
    • Tested for SAML vulnerabilities: Not applicable (no SAML endpoints)
    • Tested for OAuth2 vulnerabilities: Not applicable (no OAuth2 endpoints)
    • Tested for WebAuthn bypass: Not applicable (no WebAuthn endpoints)

  ✓ API Security Testing:
    • GraphQL introspection: Tested 1 endpoint, no issues found
    • REST API security: Skipped (API testing disabled)

  ✓ Access Control Testing:
    • IDOR testing: Skipped (no suitable endpoints)
    • SCIM vulnerabilities: No SCIM endpoints found

  ✓ Service Fingerprinting:
    • Nmap scan: 1 host scanned
      - cybermonkey.net.au: Ports 80, 443 open
      - nginx/1.24.0 detected

  Summary: 4 test categories executed, 0 vulnerabilities found
```

**Solution**: Enhance `displayOrchestratorResults()` to show test coverage details

**Estimated Time**: 2 hours

---

## Phase 3: Wire Existing Scanners (4 hours)

### P1-1: Enable IDOR Scanner

**Impact**: IDOR scanner exists but never runs
**Files**:
- `/Users/henry/Dev/shells/internal/orchestrator/bounty_engine.go:263-279`
- `/Users/henry/Dev/shells/pkg/scanners/idor/`

**Current**:
```go
// IDOR scanner initialization (pending Python worker integration)
// TODO: Will implement actual initialization when Python workers are available
// For now, IDOR testing uses direct HTTP testing as fallback
var idorScanner core.Scanner
```

**Solution**:
```go
// Initialize IDOR scanner regardless of Python workers
var idorScanner core.Scanner
if config.EnableIDORTesting {
    idorConfig := idor.Config{
        MaxDepth:      config.MaxDepth,
        Timeout:       config.ScanTimeout,
        RateLimit:     int(config.RateLimitPerSecond),
        UsePython:     pythonWorkers != nil, // Use Python if available, HTTP fallback otherwise
        PythonClient:  pythonWorkers,
    }
    idorScanner = idor.NewScanner(idorConfig, samlLogger)
    logger.Infow("IDOR scanner initialized",
        "use_python_workers", pythonWorkers != nil,
        "fallback_mode", pythonWorkers == nil,
        "component", "orchestrator",
    )
}

// Add to executeTestingPhase parallel testing
if e.idorScanner != nil && e.config.EnableIDORTesting {
    wg.Add(1)
    go func() {
        defer wg.Done()
        idorFindings := e.runIDORTests(ctx, prioritized, dbLogger)
        mu.Lock()
        allFindings = append(allFindings, idorFindings...)
        phaseResults["idor"] = createPhaseResult("idor", len(idorFindings), idorStart)
        mu.Unlock()
    }()
}
```

**Estimated Time**: 1 hour
**Validation**: Run scan, verify IDOR tests execute and findings logged

---

### P1-2: Enable REST API Scanner

**Impact**: REST API scanner exists but never initialized
**Files**:
- `/Users/henry/Dev/shells/internal/orchestrator/bounty_engine.go:263-279`
- `/Users/henry/Dev/shells/pkg/scanners/restapi/`

**Current**:
```go
// REST API scanner (pending initialization)
// TODO: Will implement actual initialization
var restAPIScanner core.Scanner
```

**Solution**:
```go
// Initialize REST API scanner
var restAPIScanner core.Scanner
if config.EnableAPITesting {
    restAPIConfig := restapi.Config{
        Timeout:      config.ScanTimeout,
        RateLimit:    int(config.RateLimitPerSecond),
        MaxEndpoints: 100,
        TestAuth:     true,
        TestIDOR:     true,
        TestRateLimit: true,
    }
    restAPIScanner = restapi.NewScanner(restAPIConfig, samlLogger)
    logger.Infow("REST API scanner initialized", "component", "orchestrator")
}

// Add field to BugBountyEngine struct:
restAPIScanner  core.Scanner // REST API security testing

// Add to executeTestingPhase parallel testing
if e.restAPIScanner != nil && e.config.EnableAPITesting {
    wg.Add(1)
    go func() {
        defer wg.Done()
        apiFindings := e.runRESTAPITests(ctx, prioritized, dbLogger)
        mu.Lock()
        allFindings = append(allFindings, apiFindings...)
        phaseResults["rest_api"] = createPhaseResult("rest_api", len(apiFindings), apiStart)
        mu.Unlock()
    }()
}

// Implement runRESTAPITests method:
func (e *BugBountyEngine) runRESTAPITests(ctx context.Context, assets []*discovery.Asset, logger *logger.Logger) []types.Finding {
    // Extract base URLs from assets
    baseURLs := extractUniqueBaseURLs(assets)

    var findings []types.Finding
    for _, url := range baseURLs {
        result, err := e.restAPIScanner.Scan(ctx, url)
        if err != nil {
            logger.Errorw("REST API scan failed", "error", err, "url", url)
            continue
        }
        findings = append(findings, result.Findings...)
    }

    return findings
}
```

**Estimated Time**: 1.5 hours
**Validation**: Run scan against API endpoint, verify auth bypass and IDOR tests execute

---

### P1-3: Fix Quick Mode to Allow Auth Discovery

**Impact**: Quick mode disables auth endpoint discovery, missing high-value vulns
**Files**: `/Users/henry/Dev/shells/internal/orchestrator/bounty_engine.go:111-125`

**Current**:
```go
if quick {
    config.SkipDiscovery = true
    config.EnableWebCrawl = false    // ❌ Disables auth endpoint discovery
    config.MaxDepth = 1
    config.EnableAuthTesting = true  // ✓ Auth testing enabled but no endpoints found
}
```

**Solution**:
```go
if quick {
    // Quick mode: Fast triage, critical vulns only (< 30 seconds total)
    config.SkipDiscovery = true
    config.DiscoveryTimeout = 5 * time.Second // Fast auth endpoint discovery
    config.ScanTimeout = 30 * time.Second
    config.TotalTimeout = 1 * time.Minute
    config.MaxAssets = 1
    config.MaxDepth = 1                     // Minimal depth for speed
    config.EnableDNS = false
    config.EnablePortScan = false
    config.EnableWebCrawl = true            // ✓ CHANGED: Allow minimal crawl for auth endpoints
    config.EnableAPITesting = false
    config.EnableLogicTesting = false
    config.EnableAuthTesting = true         // ✓ KEEP: Auth testing is high-value
    config.EnableIDORTesting = false        // Skip in quick mode
    config.EnableNucleiScan = false         // Skip in quick mode

    // Override SkipDiscovery to allow ONLY auth discovery
    config.SkipDiscovery = false            // ✓ CHANGED: Need discovery for auth endpoints
    config.DiscoveryPhaseOverride = "auth_only" // Custom flag
}
```

**Estimated Time**: 1 hour
**Validation**: Run `--quick` mode, verify SAML/OAuth2 endpoints are discovered and tested

---

## Phase 4: Integrate Checkpoint Resume (2 hours)

### P1-4: Make Checkpoint Resume Actually Skip Completed Phases

**Impact**: Resume loads checkpoint but re-runs everything anyway
**Files**:
- `/Users/henry/Dev/shells/cmd/resume.go:162-169`
- `/Users/henry/Dev/shells/internal/orchestrator/bounty_engine.go:418-799`

**Current**:
```go
// Resume.go explicitly states: "Full checkpoint resume integration pending"
// Checkpoint loads but orchestrator doesn't respect it
```

**Solution**:

```go
// 1. Add ResumeFromCheckpoint method to BugBountyEngine
func (e *BugBountyEngine) ResumeFromCheckpoint(ctx context.Context, state *checkpoint.State) (*BugBountyResult, error) {
    dbLogger.Infow("Resuming from checkpoint",
        "scan_id", state.ScanID,
        "progress", state.Progress,
        "completed_phases", state.CompletedPhases,
    )

    // Load existing result
    result := &BugBountyResult{
        ScanID:       state.ScanID,
        Target:       state.Target,
        StartTime:    state.StartedAt,
        Status:       "resuming",
        PhaseResults: make(map[string]PhaseResult),
        Findings:     state.Findings, // Restore previous findings
    }

    // Check which phases are already completed
    skipDiscovery := contains(state.CompletedPhases, "discovery")
    skipPrioritization := contains(state.CompletedPhases, "prioritization")
    skipTesting := contains(state.CompletedPhases, "testing")

    // Phase 1: Asset Discovery (skip if completed)
    var assets []*discovery.Asset
    if skipDiscovery {
        dbLogger.Infow("⏭️  Skipping discovery (already completed in checkpoint)")
        // Restore assets from checkpoint
        assets = state.DiscoveredAssets
        result.DiscoveredAt = len(assets)
    } else {
        // Run discovery normally
        assets, _ = e.executeDiscoveryPhase(ctx, state.Target, tracker, dbLogger)
        result.DiscoveredAt = len(assets)
        saveCheckpoint("discovery", 25.0, []string{"discovery"}, result.Findings)
    }

    // Phase 2: Asset Prioritization (skip if completed)
    var prioritized []*discovery.Asset
    if skipPrioritization {
        dbLogger.Infow("⏭️  Skipping prioritization (already completed in checkpoint)")
        prioritized = state.PrioritizedAssets
    } else {
        prioritized = e.executePrioritizationPhase(assets, dbLogger)
        saveCheckpoint("prioritization", 35.0, []string{"discovery", "prioritization"}, result.Findings)
    }

    // Phase 3: Vulnerability Testing (skip if completed)
    if skipTesting {
        dbLogger.Infow("⏭️  Skipping testing (already completed in checkpoint)")
        dbLogger.Infow("Proceeding directly to storage phase")
    } else {
        findings, phaseResults := e.executeTestingPhase(ctx, state.Target, prioritized, tracker, dbLogger)
        for phase, pr := range phaseResults {
            result.PhaseResults[phase] = pr
        }
        result.Findings = append(result.Findings, findings...)
        result.TestedAssets = len(prioritized)
    }

    // Phase 4: Storage (always run to save final state)
    e.storeResults(ctx, result, dbLogger)

    return result, nil
}

// 2. Update cmd/resume.go to call ResumeFromCheckpoint
func (e *BugBountyEngine) Execute(ctx context.Context, target string) (*BugBountyResult, error) {
    // Check if this is a resume operation
    if isResume {
        return e.ResumeFromCheckpoint(ctx, checkpointState)
    }

    // Normal execution path
    // ...
}
```

**Estimated Time**: 2 hours
**Validation**:
1. Start scan, interrupt with Ctrl+C after discovery
2. Resume with `shells resume <scan-id>`
3. Verify discovery is skipped and testing starts immediately

---

## Phase 5: Add Missing Query Commands (4 hours)

### P2-1: Temporal Snapshot Queries

**Impact**: Database stores snapshots but no way to compare them
**Files**: `/Users/henry/Dev/shells/cmd/results.go`

**Missing Commands**:
```bash
shells results diff <scan-id-1> <scan-id-2>      # Compare two scans
shells results history <target>                   # Show all scans for target
shells results changes <target> --since 30d       # Show changes in last 30 days
shells results compare-last <target>              # Compare to previous scan
```

**Implementation**:
```go
// Add to cmd/results.go

var diffCmd = &cobra.Command{
    Use:   "diff <scan-id-1> <scan-id-2>",
    Short: "Compare two scan results",
    Args:  cobra.ExactArgs(2),
    RunE: func(cmd *cobra.Command, args []string) error {
        scan1, err := store.GetScan(ctx, args[0])
        scan2, err := store.GetScan(ctx, args[1])

        // Compare assets
        newAssets, removedAssets := compareAssets(scan1, scan2)

        // Compare findings
        newFindings, fixedFindings := compareFindings(scan1, scan2)

        // Display diff
        displayScanDiff(scan1, scan2, newAssets, removedAssets, newFindings, fixedFindings)
        return nil
    },
}

var historyCmd = &cobra.Command{
    Use:   "history <target>",
    Short: "Show scan history for a target",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        scans, err := store.GetScansByTarget(ctx, args[0])

        // Display timeline
        for i, scan := range scans {
            fmt.Printf("%d. %s - %s (%d findings)\n",
                i+1,
                scan.CreatedAt.Format("2006-01-02 15:04"),
                scan.Status,
                len(scan.Findings),
            )
        }
        return nil
    },
}

// Display function
func displayScanDiff(scan1, scan2 *types.Scan, newAssets, removedAssets []string, newFindings, fixedFindings []types.Finding) {
    fmt.Println()
    color.Cyan("═══ Scan Comparison ═══")
    fmt.Printf("  Scan 1: %s (%s)\n", scan1.ID, scan1.CreatedAt.Format("2006-01-02"))
    fmt.Printf("  Scan 2: %s (%s)\n", scan2.ID, scan2.CreatedAt.Format("2006-01-02"))
    fmt.Println()

    // Asset changes
    if len(newAssets) > 0 {
        color.Green("  + %d new assets discovered:", len(newAssets))
        for _, asset := range newAssets {
            fmt.Printf("    • %s\n", asset)
        }
    }

    if len(removedAssets) > 0 {
        color.Red("  - %d assets no longer found:", len(removedAssets))
        for _, asset := range removedAssets {
            fmt.Printf("    • %s\n", asset)
        }
    }

    // Vulnerability changes
    if len(newFindings) > 0 {
        color.Red("  + %d new vulnerabilities:", len(newFindings))
        for _, finding := range newFindings {
            fmt.Printf("    • [%s] %s\n", finding.Severity, finding.Title)
        }
    }

    if len(fixedFindings) > 0 {
        color.Green("  ✓ %d vulnerabilities fixed:", len(fixedFindings))
        for _, finding := range fixedFindings {
            fmt.Printf("    • [%s] %s\n", finding.Severity, finding.Title)
        }
    }

    if len(newAssets) == 0 && len(removedAssets) == 0 && len(newFindings) == 0 && len(fixedFindings) == 0 {
        fmt.Println("  No changes detected")
    }
}
```

**Estimated Time**: 3 hours

---

### P2-2: Monitoring Query Commands

**Impact**: 5 monitoring tables exist but no way to query them
**Files**: `/Users/henry/Dev/shells/cmd/` (new file needed)

**Missing Commands**:
```bash
shells monitoring alerts list [--target <target>]
shells monitoring dns-changes <target> [--since 7d]
shells monitoring certificates expiring [--days 30]
shells monitoring git-changes <repo> [--since 7d]
```

**Implementation**:
```go
// Create cmd/monitoring.go

var monitoringCmd = &cobra.Command{
    Use:   "monitoring",
    Short: "Query monitoring data (alerts, DNS changes, certificate expiry, git changes)",
}

var alertsListCmd = &cobra.Command{
    Use:   "alerts",
    Short: "List monitoring alerts",
    RunE: func(cmd *cobra.Command, args []string) error {
        target, _ := cmd.Flags().GetString("target")
        alerts, err := store.GetMonitoringAlerts(ctx, target)

        for _, alert := range alerts {
            fmt.Printf("[%s] %s: %s\n",
                alert.Severity,
                alert.Target,
                alert.Message,
            )
        }
        return nil
    },
}

var dnsChangesCmd = &cobra.Command{
    Use:   "dns-changes <target>",
    Short: "Show DNS record changes for a target",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        since, _ := cmd.Flags().GetDuration("since")
        changes, err := store.GetDNSChanges(ctx, args[0], since)

        for _, change := range changes {
            fmt.Printf("%s: %s %s → %s\n",
                change.DetectedAt.Format("2006-01-02 15:04"),
                change.RecordType,
                change.OldValue,
                change.NewValue,
            )
        }
        return nil
    },
}

// Register commands in init()
func init() {
    rootCmd.AddCommand(monitoringCmd)
    monitoringCmd.AddCommand(alertsListCmd)
    monitoringCmd.AddCommand(dnsChangesCmd)
    // ... add others
}
```

**Estimated Time**: 2 hours

---

### P2-3: Scope Management Commands

**Impact**: Scope validator exists but never called from discovery
**Files**:
- `/Users/henry/Dev/shells/cmd/` (new file needed)
- `/Users/henry/Dev/shells/internal/discovery/scope_validator.go`

**Missing Commands**:
```bash
shells scope add <program-name> <scope-file>     # Add scope from file
shells scope list [--program <name>]             # List scopes
shells scope validate <target> --program <name>  # Check if target in scope
shells scope export <program-name> --format json # Export scope
```

**Integration Fix**:
```go
// In internal/discovery/engine.go, integrate scope validator:

func (e *Engine) runDiscovery(session *DiscoverySession) {
    // ... existing code

    // Before adding assets, filter through scope
    if e.scopeValidator != nil {
        validatedAssets, err := e.scopeValidator.FilterAssets(result.Assets)
        if err != nil {
            e.logger.Warn("Scope validation failed", "error", err)
        } else {
            result.Assets = validatedAssets
            e.logger.Infow("Assets filtered by scope",
                "original_count", len(result.Assets),
                "validated_count", len(validatedAssets),
            )
        }
    }
}
```

**Estimated Time**: 2 hours

---

## Phase 6: Wire Enrichment Pipeline (2 hours)

### P2-4: Enable Enrichment Pipeline

**Impact**: 12+ enrichment functions exist but never called
**Files**:
- `/Users/henry/Dev/shells/pkg/enrichment/stubs.go`
- `/Users/henry/Dev/shells/internal/orchestrator/bounty_engine.go`

**Current**: All enrichment functions return "not yet implemented"

**Solution**:
```go
// In bounty_engine.go, after vulnerability testing and before storage:

func (e *BugBountyEngine) enrichFindings(ctx context.Context, findings []types.Finding) []types.Finding {
    enriched := make([]types.Finding, 0, len(findings))

    for _, finding := range findings {
        // 1. Add exploit availability info
        exploitInfo, _ := enrichment.LookupExploits(finding.CVE)
        if exploitInfo != nil {
            finding.Metadata["exploit_available"] = exploitInfo.Available
            finding.Metadata["exploit_difficulty"] = exploitInfo.Difficulty
        }

        // 2. Add CVSS scores
        cvss, _ := enrichment.GetCVSSScore(finding.CVE)
        if cvss != nil {
            finding.Metadata["cvss_score"] = cvss.Score
            finding.Metadata["cvss_vector"] = cvss.Vector
        }

        // 3. Add remediation guidance
        remediation, _ := enrichment.GetRemediationSteps(finding.Type)
        if remediation != "" {
            finding.Remediation = remediation
        }

        // 4. Add affected versions
        if finding.Technology != "" {
            affected, _ := enrichment.GetAffectedVersions(finding.Technology, finding.CVE)
            if affected != nil {
                finding.Metadata["affected_versions"] = affected
            }
        }

        // 5. Lookup PoC/references
        references, _ := enrichment.GetVulnerabilityReferences(finding.CVE)
        if len(references) > 0 {
            finding.References = append(finding.References, references...)
        }

        enriched = append(enriched, finding)
    }

    return enriched
}

// Call before storing results:
enrichedFindings := e.enrichFindings(ctx, result.Findings)
result.Findings = enrichedFindings
```

**Implement stubs in pkg/enrichment/stubs.go**:
```go
// Replace stub implementations with real API calls

func LookupExploits(cve string) (*ExploitInfo, error) {
    // Call Exploit-DB API
    // Call Metasploit API
    // Return exploit availability
}

func GetCVSSScore(cve string) (*CVSSInfo, error) {
    // Call NVD API
    // Parse CVSS v3.1 score
}

func GetRemediationSteps(vulnerabilityType string) (string, error) {
    // Lookup in remediation knowledge base
    // Return step-by-step fix instructions
}
```

**Estimated Time**: 2 hours (basic implementation)
**Estimated Time**: 1 day (full implementation with all APIs)

---

## Phase 7: Fix Context Propagation (1 hour)

### P1-5: Discovery Engine Context Propagation

**Impact**: Discovery ignores parent timeout, can exceed time budget
**Files**: `/Users/henry/Dev/shells/internal/discovery/engine.go:228-237`

**Current**:
```go
func (e *Engine) runDiscovery(session *DiscoverySession) {
    // ❌ CRITICAL: Creating DISCONNECTED context from Background()
    ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
    // Parent context deadline is LOST here
}
```

**Solution**:
```go
// Change signature to accept parent context
func (e *Engine) runDiscovery(ctx context.Context, session *DiscoverySession) {
    // ✓ Inherit parent context and add discovery timeout
    ctx, cancel := context.WithTimeout(ctx, e.config.Timeout)
    defer cancel()

    // Log context inheritance
    if deadline, ok := ctx.Deadline(); ok {
        e.logger.Infow("Discovery context created with inherited parent deadline",
            "session_id", session.ID,
            "discovery_timeout", e.config.Timeout.String(),
            "parent_deadline", deadline.Format(time.RFC3339),
            "time_until_deadline", time.Until(deadline).String(),
        )
    }

    // ... rest of function
}

// Update StartDiscovery to pass context:
func (e *Engine) StartDiscovery(ctx context.Context, rawTarget string) (*DiscoverySession, error) {
    // ... create session

    // Start discovery in background with parent context
    go e.runDiscovery(ctx, session)

    return session, nil
}

// Update all callers in orchestrator:
func (e *BugBountyEngine) executeDiscoveryPhase(ctx context.Context, target string, tracker *progress.Tracker, logger *logger.Logger) ([]*discovery.Asset, *discovery.DiscoverySession, error) {
    session, err := e.discoveryEngine.StartDiscovery(ctx, target) // Pass context
    // ...
}
```

**Estimated Time**: 1 hour
**Validation**: Set 5-minute total timeout, verify discovery respects it and doesn't exceed allocated time

---

## Phase 8: Documentation & User Experience (2 hours)

### P3-1: Update Help Text with All Features

**Impact**: Help text doesn't mention many implemented features

**Files**:
- `/Users/henry/Dev/shells/cmd/root.go:114-167`
- All command help strings

**Solution**:
```go
// Update root command help with comprehensive feature list:
Long: `Shells - Intelligent Bug Bounty Automation Platform

Automatically discovers assets, identifies vulnerabilities, and generates
actionable findings using real security scanners.

USAGE:
  shells                      # Start web dashboard and API server (no scan)
  shells example.com          # Run scan + start dashboard automatically
  shells "Acme Corporation"   # Discover company assets and test
  shells admin@example.com    # Discover from email and test discovered assets
  shells 192.168.1.1          # Discover network and test services
  shells 192.168.1.0/24       # Scan IP range and test discovered hosts

SCAN MODES:
  shells example.com                    # Standard mode (30 min comprehensive scan)
  shells example.com --quick            # Quick mode (30 sec critical vulns only)
  shells example.com --deep             # Deep mode (comprehensive testing, 15 min)
  shells example.com --timeout 1h       # Custom timeout

COMPARISON & HISTORY:
  shells example.com --compare-to <scan-id>  # Compare with previous scan
  shells results diff <scan-1> <scan-2>      # Compare two specific scans
  shells results history example.com         # Show all scans for target
  shells results changes example.com --since 7d  # Changes in last 7 days

MONITORING:
  shells monitoring alerts               # List all alerts
  shells monitoring dns-changes example.com  # DNS record changes
  shells monitoring certificates expiring    # Certificates expiring soon

SCOPE MANAGEMENT:
  shells scope add bugcrowd bugcrowd-scope.txt   # Import scope file
  shells scope validate example.com --program bugcrowd  # Check if in scope
  shells scan example.com --scope bugcrowd-scope.txt    # Scan with scope

CHECKPOINT & RESUME:
  # Scans auto-checkpoint every 5 minutes
  # Press Ctrl+C to interrupt gracefully
  shells resume <scan-id>                # Resume interrupted scan
  shells resume --list                   # List resumable scans
  shells resume --cleanup                # Clean old checkpoints

...
```

**Estimated Time**: 1 hour

---

### P3-2: Add Progress Indicators for Long Operations

**Impact**: User sees silence during 30-second operations

**Solution**:
```go
// Add to long-running operations like org footprinting:

func (c *OrganizationCorrelator) FindOrganizationAssets(ctx context.Context, target string) (*Organization, error) {
    // Log start
    c.logger.Infow("Starting organization footprinting",
        "target", target,
        "steps", []string{"WHOIS lookup", "Certificate search", "ASN discovery"},
    )

    // Step 1: WHOIS
    c.logger.Infow("[1/3] Querying WHOIS database...")
    org, err := c.whoisClient.Lookup(target)
    if err != nil {
        c.logger.Warnw("[1/3] WHOIS lookup failed", "error", err)
    } else {
        c.logger.Infow("[1/3] ✓ WHOIS data retrieved", "organization", org.Name)
    }

    // Step 2: Certificates
    c.logger.Infow("[2/3] Searching certificate transparency logs...")
    certs, err := c.certClient.Search(target)
    if err != nil {
        c.logger.Warnw("[2/3] Certificate search failed", "error", err)
    } else {
        c.logger.Infow("[2/3] ✓ Found certificates", "count", len(certs))
    }

    // Step 3: ASN
    c.logger.Infow("[3/3] Discovering ASN and IP ranges...")
    asns, err := c.asnClient.Lookup(target)
    if err != nil {
        c.logger.Warnw("[3/3] ASN discovery failed", "error", err)
    } else {
        c.logger.Infow("[3/3] ✓ Discovered ASNs", "count", len(asns))
    }

    c.logger.Infow("Organization footprinting complete",
        "domains_found", len(org.Domains),
        "certificates_found", len(certs),
        "asns_found", len(asns),
    )

    return org, nil
}
```

**Estimated Time**: 1 hour

---

## Priority Matrix

| Priority | Feature | Time | User Impact | Complexity |
|----------|---------|------|-------------|------------|
| **P0** | HERA database schema fixes | 6h | CRITICAL - Extension broken | Medium |
| **P0** | Display organization footprinting results | 2h | HIGH - No visibility | Easy |
| **P0** | Display asset discovery results | 3h | HIGH - No visibility | Easy |
| **P0** | Display vulnerability test coverage | 2h | HIGH - No visibility | Easy |
| **P0** | Fix organization footprinting failures | 4h | CRITICAL - Zero discovery | Medium |
| **P1** | Enable IDOR scanner | 1h | MEDIUM - Missing tests | Easy |
| **P1** | Enable REST API scanner | 1.5h | MEDIUM - Missing tests | Easy |
| **P1** | Fix quick mode auth discovery | 1h | MEDIUM - Missing vulns | Easy |
| **P1** | Checkpoint resume skip completed | 2h | MEDIUM - Time savings | Medium |
| **P1** | Fix discovery context propagation | 1h | HIGH - Timeout issues | Easy |
| **P2** | Temporal snapshot queries | 3h | MEDIUM - Comparison | Medium |
| **P2** | Monitoring query commands | 2h | LOW - Unused tables | Easy |
| **P2** | Scope management integration | 2h | LOW - Unused feature | Medium |
| **P2** | Enrichment pipeline | 2h | MEDIUM - Better findings | Medium |
| **P3** | Help text updates | 1h | LOW - Documentation | Easy |
| **P3** | Progress indicators | 1h | LOW - UX polish | Easy |

---

## Implementation Schedule

### Week 1 (40 hours)

**Days 1-2: Critical Fixes (P0)**
- [ ] Fix HERA database schema mismatches (6h)
- [ ] Fix organization footprinting failures (4h)
- [ ] Display organization footprinting results (2h)
- [ ] Display asset discovery results (3h)
- [ ] Display vulnerability test coverage (2h)

**Days 3-4: Scanner Integration (P1)**
- [ ] Enable IDOR scanner (1h)
- [ ] Enable REST API scanner (1.5h)
- [ ] Fix quick mode auth discovery (1h)
- [ ] Fix discovery context propagation (1h)
- [ ] Checkpoint resume skip completed phases (2h)

**Day 5: Query Commands (P2)**
- [ ] Temporal snapshot queries (3h)
- [ ] Monitoring query commands (2h)
- [ ] Scope management integration (2h)

### Week 2 (20 hours)

**Days 1-2: Enrichment & Polish**
- [ ] Enrichment pipeline integration (2h)
- [ ] Progress indicators for long operations (1h)
- [ ] Help text comprehensive update (1h)

**Days 3-5: Testing & Validation**
- [ ] End-to-end testing of all wired features
- [ ] Bug fixes and refinements
- [ ] Documentation updates
- [ ] Performance testing

---

## Success Criteria

**Phase 1 Complete When**:
- ✅ HERA browser extension works against shells server
- ✅ `shells cybermonkey.net.au` discovers related Code Monkey domains
- ✅ Organization footprinting results displayed in console

**Phase 2 Complete When**:
- ✅ Discovery results show subdomains, IPs, services with versions
- ✅ Vulnerability test coverage displayed (what was tested, what was found)
- ✅ User can understand what happened without reading logs

**Phase 3 Complete When**:
- ✅ IDOR scanner runs and reports findings
- ✅ REST API scanner runs and tests auth bypass
- ✅ Quick mode discovers and tests auth endpoints

**Phase 4 Complete When**:
- ✅ `shells resume <scan-id>` skips already-completed phases
- ✅ Resume shows "Skipping discovery (already completed)"
- ✅ Checkpoint saves and restores work correctly

**Phase 5 Complete When**:
- ✅ `shells results diff` compares two scans
- ✅ `shells results history` shows scan timeline
- ✅ `shells monitoring alerts` lists alerts
- ✅ `shells scope validate` checks target scope

**All Phases Complete When**:
- ✅ All implemented features are wired and accessible
- ✅ Database schema matches code expectations
- ✅ User can access all stored data via CLI
- ✅ Help text documents all features
- ✅ No "not yet implemented" stubs in critical paths

---

## Maintenance Notes

After implementation, add to CI/CD:

1. **Integration Tests**: Test orchestrator wiring end-to-end
2. **Schema Validation**: Ensure database schema matches queries
3. **Feature Completeness**: Automated check for "not yet implemented" in critical paths
4. **Display Tests**: Verify all results have display functions
5. **Context Propagation**: Validate timeout behavior in all phases

---

**Plan created**: 2025-10-23
**Estimated total time**: ~60 hours (1.5 weeks full-time)
**Risk areas**: External API integrations (WHOIS, cert transparency), ML model implementation
**High ROI wins**: Display functions (high impact, low effort), Scanner initialization (easy fixes)
