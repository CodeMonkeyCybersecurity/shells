# Intelligence Loop Improvement Plan - Adversarial Analysis

**Date**: 2025-10-30
**Status**: Detailed implementation roadmap based on comprehensive codebase analysis

---

## Executive Summary

### Current State Assessment

**What's Working** ✅:
- Phase-based pipeline architecture with 8 clear phases
- Feedback loop infrastructure (3 iteration limit)
- Enhanced certificate client with TLS fallback (implemented but not used)
- Cloud asset discovery (AWS, Azure, GCP)
- ProjectDiscovery tool integration framework
- Organization context tracking

**Critical Issues** ⚠️:
1. **EnhancedCertificateClient exists but DefaultCertificateClient is used** (no fallback in production)
2. **OrganizationCorrelator clients are nil** (WHOIS, ASN, Certificate clients never initialized)
3. **AssetRelationshipMapping may not be enabled** (config unclear)
4. **Subfinder/Httpx return mock data** (not actually integrated)
5. **No multi-source confidence scoring** (assets not validated across sources)
6. **No iteration depth tracking** (can cause scope creep)

**Impact**: The microsoft.com → azure.com → office.com discovery chain **does not work end-to-end**.

---

## Part 1: Critical Fixes (P0) - Enable Core Intelligence Loop

### Fix 1: Wire EnhancedCertificateClient into Production

**Problem**: [pkg/correlation/default_clients.go:76-80](pkg/correlation/default_clients.go#L76-L80) creates DefaultCertificateClient which has no fallback when crt.sh fails.

**Solution**: Use EnhancedCertificateClient which tries:
1. Direct TLS connection (fast, reliable)
2. crt.sh HTTP API (fallback)
3. Future: PostgreSQL, Censys

**Files to Modify**:

#### File 1: [pkg/correlation/default_clients.go](pkg/correlation/default_clients.go)

**Current code** (lines 76-80):
```go
func NewDefaultCertificateClient(logger *logger.Logger) CertificateClient {
	return &DefaultCertificateClient{
		logger:   logger,
		ctClient: certlogs.NewCTLogClient(logger),
	}
}
```

**Change to**:
```go
func NewDefaultCertificateClient(logger *logger.Logger) CertificateClient {
	// Use enhanced client with multiple fallback sources
	return NewEnhancedCertificateClient(logger)
}
```

**Impact**: All certificate queries will now try direct TLS first, then fall back to CT logs.

**Test**: Run `go run test_cert_enhanced.go` to verify fallback chain works.

---

### Fix 2: Initialize OrganizationCorrelator Clients

**Problem**: [pkg/correlation/organization.go:165-181](pkg/correlation/organization.go#L165-L181) shows `SetClients()` must be called, but clients are never initialized in the pipeline.

**Root cause**: When clients are nil, these methods silently fail:
- Lines 329-346: WHOIS lookup skipped (`if oc.whoisClient != nil`)
- Lines 349-384: Certificate lookup skipped (`if oc.certClient != nil`)
- Lines 391-406: ASN lookup skipped (`if oc.asnClient != nil`)

**Solution**: Initialize clients when creating OrganizationCorrelator.

**Files to Modify**:

#### File 1: [internal/discovery/asset_relationship_mapper.go](internal/discovery/asset_relationship_mapper.go)

**Find the NewAssetRelationshipMapper function** (around line 97):

**Current code**:
```go
func NewAssetRelationshipMapper(config *DiscoveryConfig, logger *logger.Logger) *AssetRelationshipMapper {
	return &AssetRelationshipMapper{
		assets:               make(map[string]*Asset),
		relationships:        make(map[string]*AssetRelationship),
		config:               config,
		logger:               logger,
		orgCorrelator:        correlation.NewEnhancedOrganizationCorrelator(corrCfg, logger),
		certDiscoverer:       NewCertificateDiscoverer(logger),
		// ... other fields
	}
}
```

**Add after orgCorrelator creation**:
```go
func NewAssetRelationshipMapper(config *DiscoveryConfig, logger *logger.Logger) *AssetRelationshipMapper {
	// Create correlator config
	corrCfg := correlation.CorrelatorConfig{
		EnableWhois:     true,
		EnableCerts:     true,
		EnableASN:       true,
		EnableTrademark: false, // Optional
		EnableLinkedIn:  false, // Optional
		EnableGitHub:    false, // Optional
		EnableCloud:     true,
		CacheTTL:        24 * time.Hour,
		MaxWorkers:      5,
	}

	// Create correlator
	orgCorrelator := correlation.NewEnhancedOrganizationCorrelator(corrCfg, logger)

	// **NEW: Initialize clients**
	whoisClient := correlation.NewDefaultWhoisClient(logger)
	certClient := correlation.NewDefaultCertificateClient(logger) // Uses enhanced client after Fix 1
	asnClient := correlation.NewDefaultASNClient(logger)
	cloudClient := correlation.NewDefaultCloudClient(logger)

	// Wire up clients
	orgCorrelator.SetClients(
		whoisClient,
		certClient,
		asnClient,
		nil, // trademark (optional)
		nil, // linkedin (optional)
		nil, // github (optional)
		cloudClient,
	)

	return &AssetRelationshipMapper{
		assets:               make(map[string]*Asset),
		relationships:        make(map[string]*AssetRelationship),
		config:               config,
		logger:               logger,
		orgCorrelator:        orgCorrelator, // Now has clients initialized!
		certDiscoverer:       NewCertificateDiscoverer(logger),
		// ... other fields
	}
}
```

**Impact**: WHOIS, Certificate, and ASN lookups will now actually execute instead of silently skipping.

---

### Fix 3: Verify AssetRelationshipMapping is Enabled

**Problem**: [internal/orchestrator/phase_reconnaissance.go:104-106](internal/orchestrator/phase_reconnaissance.go#L104-L106) checks `if p.config.EnableAssetRelationshipMapping` but this config may not be set.

**Investigation needed**:

#### File 1: Check [internal/orchestrator/bounty_engine.go](internal/orchestrator/bounty_engine.go)

**Find DefaultBugBountyConfig()** (around line 215):

**Verify this exists**:
```go
func DefaultBugBountyConfig() *BugBountyConfig {
	return &BugBountyConfig{
		// ... other configs
		EnableAssetRelationshipMapping: true,  // MUST be true
		// ...
	}
}
```

**If not present, add it**.

#### File 2: Check [internal/config/config.go](internal/config/config.go)

**Verify BugBountyConfig struct has the field**:
```go
type BugBountyConfig struct {
	// ... other fields
	EnableAssetRelationshipMapping bool                    `yaml:"enable_asset_relationship_mapping"`
	DiscoveryConfig                *discovery.DiscoveryConfig `yaml:"discovery_config"`
	// ...
}
```

**Impact**: Asset relationship mapping will run by default, enabling organization correlation.

---

## Part 2: High Priority Enhancements (P1)

### Enhancement 1: Multi-Source Confidence Scoring

**Problem**: Assets are discovered but not validated across multiple sources. No way to know if an asset is real or a false positive.

**Solution**: Track which sources discovered each asset and calculate confidence score.

**Implementation**:

#### File 1: [internal/discovery/types.go](internal/discovery/types.go)

**Modify Asset struct** (around line 50):

**Add fields**:
```go
type Asset struct {
	ID               string                 `json:"id"`
	Type             AssetType              `json:"type"`
	Value            string                 `json:"value"`
	Source           string                 `json:"source"`           // Primary source
	Sources          []string               `json:"sources"`          // **NEW: All sources**
	Confidence       float64                `json:"confidence"`       // Already exists
	DiscoveredAt     time.Time              `json:"discovered_at"`
	LastSeenAt       time.Time              `json:"last_seen_at"`    // **NEW**
	DiscoveryDepth   int                    `json:"discovery_depth"` // **NEW: Hops from seed**
	ParentAssetID    string                 `json:"parent_asset_id"` // **NEW: Discovery chain**
	Metadata         map[string]interface{} `json:"metadata"`
	Tags             []string               `json:"tags"`
	Relationships    []string               `json:"relationships"`
	Technologies     []string               `json:"technologies"`
	Vulnerabilities  []string               `json:"vulnerabilities"`
	Notes            string                 `json:"notes"`
}
```

#### File 2: Create [internal/discovery/confidence.go](internal/discovery/confidence.go) (NEW FILE)

```go
package discovery

import "time"

// SourceWeights defines trust levels for different discovery sources
var SourceWeights = map[string]float64{
	// Passive sources (high trust - externally verified)
	"crt.sh":           0.95, // Certificate transparency logs
	"censys":           0.90, // Scanned and verified
	"subfinder":        0.85, // Aggregates multiple passive sources
	"whois":            0.90, // Authoritative registration data
	"asn":              0.85, // BGP routing data
	"reverse_dns":      0.80, // PTR records

	// Active probing (medium-high trust - directly verified)
	"httpx":            0.85, // Live HTTP probe
	"dnsx":             0.80, // DNS resolution
	"tls_direct":       0.95, // Direct TLS connection

	// Active enumeration (medium trust - may have false positives)
	"dns_bruteforce":   0.50, // Wordlist-based
	"permutation":      0.40, // Algorithmic generation
	"crawl":            0.70, // Found in links

	// Extracted from findings (low-medium trust - context-dependent)
	"finding_metadata": 0.60, // From vulnerability evidence
	"response_body":    0.50, // Parsed from HTTP responses
	"javascript":       0.55, // Extracted from JS files
}

// CalculateMultiSourceConfidence computes confidence based on source diversity
func CalculateMultiSourceConfidence(sources []string) float64 {
	if len(sources) == 0 {
		return 0.0
	}

	// Accumulate weighted confidence
	totalWeight := 0.0
	uniqueSources := make(map[string]bool)

	for _, source := range sources {
		if uniqueSources[source] {
			continue // Don't count duplicate sources
		}
		uniqueSources[source] = true

		weight, exists := SourceWeights[source]
		if !exists {
			weight = 0.5 // Default for unknown sources
		}
		totalWeight += weight
	}

	// Normalize by number of unique sources (diminishing returns)
	sourceCount := float64(len(uniqueSources))
	baseScore := totalWeight / sourceCount

	// Bonus for multiple sources (max +0.15)
	diversityBonus := 0.0
	if sourceCount >= 2 {
		diversityBonus = 0.05
	}
	if sourceCount >= 3 {
		diversityBonus = 0.10
	}
	if sourceCount >= 4 {
		diversityBonus = 0.15
	}

	confidence := baseScore + diversityBonus

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// MergeAssetSources combines duplicate assets from multiple sources
func MergeAssetSources(existing *Asset, new *Asset) *Asset {
	// Add new source if not already present
	sourceExists := false
	for _, s := range existing.Sources {
		if s == new.Source {
			sourceExists = true
			break
		}
	}

	if !sourceExists {
		existing.Sources = append(existing.Sources, new.Source)
	}

	// Recalculate confidence
	existing.Confidence = CalculateMultiSourceConfidence(existing.Sources)

	// Update last seen time
	existing.LastSeenAt = time.Now()

	// Merge metadata (prefer higher confidence source)
	if new.Confidence > existing.Confidence {
		for k, v := range new.Metadata {
			existing.Metadata[k] = v
		}
	}

	// Merge tags
	for _, tag := range new.Tags {
		hasTag := false
		for _, existingTag := range existing.Tags {
			if existingTag == tag {
				hasTag = true
				break
			}
		}
		if !hasTag {
			existing.Tags = append(existing.Tags, tag)
		}
	}

	return existing
}

// FilterLowConfidenceAssets removes assets below threshold
func FilterLowConfidenceAssets(assets []*Asset, minConfidence float64) []*Asset {
	filtered := make([]*Asset, 0, len(assets))
	for _, asset := range assets {
		if asset.Confidence >= minConfidence {
			filtered = append(filtered, asset)
		}
	}
	return filtered
}
```

#### File 3: Modify [internal/discovery/engine.go](internal/discovery/engine.go)

**Find processDiscoveryResult()** (around line 420):

**Add source tracking**:
```go
func (e *Engine) processDiscoveryResult(ctx context.Context, result *DiscoveryResult) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Check if asset already discovered
	existing, exists := e.state.Assets[result.Asset.Value]

	if exists {
		// Merge with existing asset
		existing = MergeAssetSources(existing, result.Asset)
		e.state.Assets[result.Asset.Value] = existing

		e.logger.Debugw("Asset seen from additional source",
			"asset", result.Asset.Value,
			"new_source", result.Asset.Source,
			"total_sources", len(existing.Sources),
			"confidence", existing.Confidence,
		)
	} else {
		// New asset discovery
		result.Asset.Sources = []string{result.Asset.Source}
		result.Asset.Confidence = CalculateMultiSourceConfidence(result.Asset.Sources)
		result.Asset.DiscoveredAt = time.Now()
		result.Asset.LastSeenAt = time.Now()

		e.state.Assets[result.Asset.Value] = result.Asset

		e.logger.Infow("New asset discovered",
			"asset", result.Asset.Value,
			"type", result.Asset.Type,
			"source", result.Asset.Source,
			"confidence", result.Asset.Confidence,
		)
	}

	return nil
}
```

**Impact**:
- Assets validated by multiple sources get higher confidence (e.g., found by both crt.sh AND subfinder = 0.90 confidence)
- Assets from single low-trust source (e.g., DNS bruteforce only) get lower confidence (0.50)
- Can filter assets by confidence threshold before expensive operations

---

### Enhancement 2: Iteration Depth Tracking

**Problem**: No tracking of "how many hops from seed target". Can cause infinite loops or scope creep.

**Solution**: Track discovery depth for each asset and apply depth limits.

**Implementation**:

#### File 1: [internal/discovery/types.go](internal/discovery/types.go) - Already added DiscoveryDepth field above

#### File 2: Modify [internal/orchestrator/pipeline.go](internal/orchestrator/pipeline.go)

**Find extractNewAssetsFromFindings()** (around line 597):

**Add depth tracking**:
```go
func (p *Pipeline) extractNewAssetsFromFindings() []discovery.Asset {
	newAssets := []discovery.Asset{}
	seenAssets := make(map[string]bool)

	// Track existing assets
	for _, asset := range p.state.DiscoveredAssets {
		seenAssets[asset.Value] = true
	}

	// Current iteration depth
	currentDepth := p.state.CurrentIteration

	for _, finding := range p.state.RawFindings {
		if finding.Evidence != "" {
			extracted := extractAssetsFromText(finding.Evidence)
			for _, asset := range extracted {
				if !seenAssets[asset.Value] {
					// **NEW: Set discovery depth and parent**
					asset.DiscoveryDepth = currentDepth
					asset.ParentAssetID = finding.TargetAsset // Track discovery chain
					asset.Sources = []string{"finding_metadata"}

					// **NEW: Check if within depth limit**
					if currentDepth >= p.config.MaxIterationDepth {
						p.logger.Debugw("Asset exceeds depth limit, skipping",
							"asset", asset.Value,
							"depth", currentDepth,
							"max_depth", p.config.MaxIterationDepth,
						)
						continue
					}

					newAssets = append(newAssets, asset)
					seenAssets[asset.Value] = true
				}
			}
		}

		// Extract from metadata
		if endpoint, ok := finding.Metadata["endpoint"].(string); ok && endpoint != "" {
			asset := discovery.Asset{
				ID:             uuid.New().String(),
				Type:           discovery.AssetTypeURL,
				Value:          endpoint,
				Source:         "finding_metadata",
				Sources:        []string{"finding_metadata"},
				Confidence:     0.6, // From finding evidence
				DiscoveredAt:   time.Now(),
				DiscoveryDepth: currentDepth,       // **NEW**
				ParentAssetID:  finding.TargetAsset, // **NEW**
			}

			// **NEW: Check depth limit**
			if currentDepth >= p.config.MaxIterationDepth {
				continue
			}

			if !seenAssets[asset.Value] {
				newAssets = append(newAssets, asset)
				seenAssets[asset.Value] = true
			}
		}
	}

	return newAssets
}
```

#### File 3: Add depth limit to config

**Modify [internal/orchestrator/bounty_engine.go](internal/orchestrator/bounty_engine.go)**:

```go
type BugBountyConfig struct {
	// ... existing fields
	MaxIterationDepth              int  `yaml:"max_iteration_depth"` // **NEW**
	// ...
}

func DefaultBugBountyConfig() *BugBountyConfig {
	return &BugBountyConfig{
		// ... existing defaults
		MaxIterationDepth:              3, // **NEW: Stop after 3 hops from seed**
		// ...
	}
}
```

**Impact**:
- Prevents infinite discovery loops
- Limits scope creep (depth 1 = direct assets, depth 2 = 1 hop away, depth 3 = 2 hops)
- Can visualize discovery chains (seed → cert SAN → subdomain → API endpoint)

---

### Enhancement 3: Certificate Organization Pivot

**Problem**: Can extract organization from certificates but can't search for ALL certificates belonging to that organization.

**Solution**: Add SearchByOrganization to certificate clients.

**Implementation**:

#### File 1: Enhance [pkg/correlation/cert_client_enhanced.go](pkg/correlation/cert_client_enhanced.go)

**Add method** (after line 141):

```go
// SearchByOrganization finds all certificates for an organization
func (c *EnhancedCertificateClient) SearchByOrganization(ctx context.Context, org string) ([]CertificateInfo, error) {
	c.logger.Infow("Searching certificates by organization",
		"organization", org,
	)

	// Strategy 1: Try Censys if API key available
	// Censys has best organization search capability
	// TODO: Add Censys client when API keys configured

	// Strategy 2: Try crt.sh with O= search
	// crt.sh supports organization field search
	orgQuery := fmt.Sprintf("O=%s", org)
	certs, err := c.ctClient.SearchDomain(ctx, orgQuery)
	if err == nil && len(certs) > 0 {
		certInfos := c.convertCTLogCerts(certs)
		c.logger.Infow("Certificates found by organization search",
			"organization", org,
			"certificates_found", len(certInfos),
			"method", "crtsh_org",
		)
		return certInfos, nil
	}

	if err != nil {
		c.logger.Warnw("Organization certificate search failed",
			"organization", org,
			"error", err,
		)
	}

	// Return empty on failure (graceful degradation)
	return []CertificateInfo{}, nil
}
```

#### File 2: Use in [internal/discovery/asset_relationship_mapper.go](internal/discovery/asset_relationship_mapper.go)

**Find buildCertificateRelationships()** (around line 350):

**Add organization pivot**:
```go
func (arm *AssetRelationshipMapper) buildCertificateRelationships(ctx context.Context) error {
	certAssets := arm.getAssetsByType(AssetTypeCertificate)

	for _, certAsset := range certAssets {
		// Existing logic: Get certs for domain
		certs, err := arm.orgCorrelator.GetCertificates(ctx, certAsset.Value)

		// Extract SANs (existing)
		for _, cert := range certs {
			for _, san := range cert.SANs {
				// Add SAN as related domain...
			}
		}

		// **NEW: Organization pivot**
		// If certificate has organization name, find ALL org certificates
		for _, cert := range certs {
			if cert.Organization != "" && cert.Organization != "Unknown" {
				arm.logger.Infow("Pivoting on certificate organization",
					"organization", cert.Organization,
					"source_domain", certAsset.Value,
				)

				// Search for ALL certificates with this organization
				orgCerts, err := arm.certClient.SearchByOrganization(ctx, cert.Organization)
				if err != nil {
					arm.logger.Warnw("Organization pivot failed",
						"organization", cert.Organization,
						"error", err,
					)
					continue
				}

				arm.logger.Infow("Organization pivot completed",
					"organization", cert.Organization,
					"certificates_found", len(orgCerts),
				)

				// Extract domains from ALL organization certificates
				for _, orgCert := range orgCerts {
					for _, san := range orgCert.SANs {
						if !strings.HasPrefix(san, "*.") {
							// Add as discovered domain with high confidence
							discoveredAsset := &Asset{
								ID:             uuid.New().String(),
								Type:           AssetTypeDomain,
								Value:          san,
								Source:         "cert_org_pivot",
								Sources:        []string{"cert_org_pivot", "crt.sh"},
								Confidence:     0.85, // High confidence from org correlation
								DiscoveredAt:   time.Now(),
								DiscoveryDepth: certAsset.DiscoveryDepth + 1,
								ParentAssetID:  certAsset.ID,
								Metadata: map[string]interface{}{
									"organization":   cert.Organization,
									"issuer":         orgCert.Issuer,
									"discovery_path": "org_cert_pivot",
								},
							}

							arm.addAsset(discoveredAsset)

							// Create relationship
							arm.addRelationship(&AssetRelationship{
								ID:             uuid.New().String(),
								SourceAssetID:  certAsset.ID,
								TargetAssetID:  discoveredAsset.ID,
								Type:           "same_organization",
								Confidence:     0.85,
								Source:         "certificate_correlation",
								CreatedAt:      time.Now(),
								Metadata: map[string]interface{}{
									"organization": cert.Organization,
								},
							})
						}
					}
				}

				// Only pivot once per organization (cache results)
				break
			}
		}
	}

	return nil
}
```

**Impact**: When discovering microsoft.com certificate with O=Microsoft Corporation, will find ALL Microsoft certificates and extract domains: azure.com, office.com, live.com, xbox.com, skype.com, etc.

---

## Part 3: Medium Priority Improvements (P2)

### Improvement 1: Add Censys Integration

**File**: Create [pkg/discovery/external/censys_cert.go](pkg/discovery/external/censys_cert.go)

```go
package external

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/correlation"
)

type CensysCertClient struct {
	apiID     string
	apiSecret string
	client    *http.Client
	logger    *logger.Logger
}

func NewCensysCertClient(apiID, apiSecret string, logger *logger.Logger) *CensysCertClient {
	return &CensysCertClient{
		apiID:     apiID,
		apiSecret: apiSecret,
		client:    &http.Client{Timeout: 30 * time.Second},
		logger:    logger,
	}
}

func (c *CensysCertClient) SearchByOrganization(ctx context.Context, org string) ([]correlation.CertificateInfo, error) {
	url := "https://search.censys.io/api/v2/certificates/search"
	query := fmt.Sprintf("parsed.subject.organization:%s", org)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	q := req.URL.Query()
	q.Add("q", query)
	q.Add("per_page", "100")
	req.URL.RawQuery = q.Encode()

	// Basic auth
	req.SetBasicAuth(c.apiID, c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("censys returned status %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		Result struct {
			Hits []struct {
				Names []string `json:"names"` // SANs
				Parsed struct {
					Subject struct {
						Organization []string `json:"organization"`
					} `json:"subject"`
					Issuer struct {
						CommonName string `json:"common_name"`
					} `json:"issuer"`
					Validity struct {
						Start string `json:"start"`
						End   string `json:"end"`
					} `json:"validity"`
				} `json:"parsed"`
			} `json:"hits"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Convert to CertificateInfo
	certs := make([]correlation.CertificateInfo, 0, len(result.Result.Hits))
	for _, hit := range result.Result.Hits {
		cert := correlation.CertificateInfo{
			SANs:   hit.Names,
			Issuer: hit.Parsed.Issuer.CommonName,
		}

		if len(hit.Parsed.Subject.Organization) > 0 {
			cert.Organization = hit.Parsed.Subject.Organization[0]
		}

		// Parse timestamps
		if start, err := time.Parse(time.RFC3339, hit.Parsed.Validity.Start); err == nil {
			cert.NotBefore = start
		}
		if end, err := time.Parse(time.RFC3339, hit.Parsed.Validity.End); err == nil {
			cert.NotAfter = end
		}

		certs = append(certs, cert)
	}

	c.logger.Infow("Censys organization search completed",
		"organization", org,
		"certificates_found", len(certs),
	)

	return certs, nil
}
```

**Configuration**: Add to `.shells.yaml`:
```yaml
apis:
  censys:
    api_id: "${CENSYS_API_ID}"
    api_secret: "${CENSYS_API_SECRET}"
    enabled: true
```

---

### Improvement 2: Add Nameserver (NS) Correlation

**File**: Create [pkg/discovery/dns/ns_correlation.go](pkg/discovery/dns/ns_correlation.go)

```go
package dns

import (
	"context"
	"net"
	"strings"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

type NSCorrelator struct {
	logger *logger.Logger
	// Future: WhoisXML API client for reverse NS lookup
}

func NewNSCorrelator(logger *logger.Logger) *NSCorrelator {
	return &NSCorrelator{logger: logger}
}

// GetNameservers returns NS records for a domain
func (n *NSCorrelator) GetNameservers(ctx context.Context, domain string) ([]string, error) {
	ns, err := net.LookupNS(domain)
	if err != nil {
		return nil, err
	}

	nameservers := make([]string, len(ns))
	for i, server := range ns {
		nameservers[i] = strings.TrimSuffix(server.Host, ".")
	}

	return nameservers, nil
}

// IsSharedHosting determines if NS is shared hosting provider
func (n *NSCorrelator) IsSharedHosting(ns string) bool {
	sharedProviders := []string{
		"cloudflare.com",
		"awsdns",
		"azure-dns",
		"googledomains.com",
		"domaincontrol.com", // GoDaddy
		"registrar-servers.com", // Namecheap
		"dnsmadeeasy.com",
		"nsone.net",
		"ultradns.com",
	}

	for _, provider := range sharedProviders {
		if strings.Contains(strings.ToLower(ns), provider) {
			return true
		}
	}

	return false
}

// CorrelateByNameserver finds relationship between domains
func (n *NSCorrelator) CorrelateByNameserver(ctx context.Context, domain1, domain2 string) (bool, float64) {
	ns1, err1 := n.GetNameservers(ctx, domain1)
	ns2, err2 := n.GetNameservers(ctx, domain2)

	if err1 != nil || err2 != nil {
		return false, 0.0
	}

	// Check for overlap
	nsMap := make(map[string]bool)
	for _, ns := range ns1 {
		nsMap[ns] = true
	}

	matchCount := 0
	for _, ns := range ns2 {
		if nsMap[ns] {
			matchCount++
		}
	}

	if matchCount == 0 {
		return false, 0.0
	}

	// Calculate confidence
	// Same NS = high correlation UNLESS shared hosting
	if n.IsSharedHosting(ns1[0]) {
		// Shared hosting - low confidence
		return true, 0.2
	}

	// Dedicated/custom NS - high confidence
	confidence := 0.7 + (float64(matchCount) / float64(len(ns1)) * 0.2)
	return true, confidence
}
```

**Usage in asset_relationship_mapper.go**:
```go
// Check NS correlation
nsCorrelator := dns.NewNSCorrelator(arm.logger)
correlated, confidence := nsCorrelator.CorrelateByNameserver(ctx, domain1, domain2)
if correlated && confidence > 0.5 {
	// Add relationship
}
```

---

## Part 4: Implementation Sequence

### Week 1: Critical Fixes (P0)

**Day 1-2**:
1. ✅ Implement Fix 1: Wire EnhancedCertificateClient (1 line change + testing)
2. ✅ Implement Fix 2: Initialize OrganizationCorrelator clients (20-30 lines)
3. ✅ Implement Fix 3: Verify AssetRelationshipMapping config (verification + fix if needed)

**Day 3-4**:
4. ✅ Test end-to-end: Run `shells microsoft.com` and verify:
   - Direct TLS certificate retrieval works
   - WHOIS lookup executes (not skipped)
   - Certificate SANs extracted
   - Related domains discovered
5. ✅ Test with smaller domain: `shells anthropic.com` (faster, less data)

**Day 5**:
6. ✅ Document what's working vs not working
7. ✅ Create test cases for regression prevention

**Deliverable**: microsoft.com → azure.com → office.com discovery works end-to-end

---

### Week 2: High Priority Enhancements (P1)

**Day 1-2**:
1. ✅ Implement Enhancement 1: Multi-source confidence scoring
   - Create confidence.go (150 lines)
   - Modify Asset struct (5 lines)
   - Modify processDiscoveryResult() (30 lines)

**Day 3**:
2. ✅ Implement Enhancement 2: Iteration depth tracking
   - Modify extractNewAssetsFromFindings() (20 lines)
   - Add depth limit to config (5 lines)

**Day 4-5**:
3. ✅ Implement Enhancement 3: Certificate organization pivot
   - Add SearchByOrganization() to cert client (40 lines)
   - Add org pivot to buildCertificateRelationships() (60 lines)
   - Test with microsoft.com

**Deliverable**:
- Assets have confidence scores (0.0-1.0)
- Discovery depth prevents infinite loops
- Organization pivot discovers ALL company domains

---

### Week 3-4: Medium Priority (P2) + Testing

**Week 3**:
1. Implement Censys integration (optional, if API key available)
2. Implement NS correlation
3. Add API usage tracking
4. Enhance caching layer

**Week 4**:
1. Comprehensive testing with multiple targets
2. Performance optimization
3. Documentation updates
4. Bug fixes

---

## Part 5: Testing Strategy

### Unit Tests

**File**: [internal/discovery/confidence_test.go](internal/discovery/confidence_test.go)
```go
func TestCalculateMultiSourceConfidence(t *testing.T) {
	tests := []struct {
		name     string
		sources  []string
		expected float64
	}{
		{
			name:     "Single high-trust source",
			sources:  []string{"crt.sh"},
			expected: 0.95,
		},
		{
			name:     "Multiple sources with diversity bonus",
			sources:  []string{"crt.sh", "subfinder", "httpx"},
			expected: 1.0, // 0.90 base + 0.10 diversity
		},
		{
			name:     "Low-trust source",
			sources:  []string{"dns_bruteforce"},
			expected: 0.50,
		},
		{
			name:     "Duplicate sources (no double counting)",
			sources:  []string{"crt.sh", "crt.sh", "crt.sh"},
			expected: 0.95, // Same as single source
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateMultiSourceConfidence(tt.sources)
			if result != tt.expected {
				t.Errorf("Expected %f, got %f", tt.expected, result)
			}
		})
	}
}
```

### Integration Tests

**File**: [internal/orchestrator/intelligence_loop_integration_test.go](internal/orchestrator/intelligence_loop_integration_test.go)

```go
func TestIntelligenceLoop_MicrosoftDiscovery(t *testing.T) {
	// Setup
	engine := setupTestEngine(t)

	// Execute
	result, err := engine.ExecuteWithPipeline(context.Background(), "microsoft.com")
	require.NoError(t, err)

	// Verify discovered domains
	discoveredDomains := extractDomains(result.DiscoveredAssets)

	// Assert: Key Microsoft properties discovered
	assert.Contains(t, discoveredDomains, "azure.com", "azure.com should be discovered via certificate SANs")
	assert.Contains(t, discoveredDomains, "office.com", "office.com should be discovered via certificate SANs")
	assert.Contains(t, discoveredDomains, "live.com", "live.com should be discovered via certificate SANs")

	// Assert: Organization context built
	assert.NotNil(t, result.OrganizationInfo)
	assert.Equal(t, "Microsoft Corporation", result.OrganizationInfo.Name)

	// Assert: Assets have confidence scores
	for _, asset := range result.DiscoveredAssets {
		assert.GreaterOrEqual(t, asset.Confidence, 0.0)
		assert.LessOrEqual(t, asset.Confidence, 1.0)
		assert.NotEmpty(t, asset.Sources, "Asset should have at least one source")
	}
}
```

### Manual Testing Checklist

**Test 1: Certificate Discovery**
```bash
# Run enhanced certificate client test
go run test_cert_enhanced.go

# Expected: anthropic.com, github.com, cloudflare.com return certificates via direct TLS
# Expected: SANs extracted (3, 2, 2 respectively)
```

**Test 2: Organization Correlation**
```bash
# Run full pipeline with microsoft.com
./shells microsoft.com --log-level info

# Expected output:
# ✓ WHOIS lookup: Microsoft Corporation
# ✓ Certificate discovered: 1+ certs
# ✓ SANs extracted: 30+ domains
# ✓ Organization pivot: Search for O=Microsoft Corporation
# ✓ Related domains: azure.com, office.com, live.com, outlook.com, ...
# ✓ Confidence scores: 0.85-0.95 for cert-based discoveries
```

**Test 3: Iteration Depth**
```bash
# Run with depth tracking enabled
./shells microsoft.com --max-depth 2

# Expected:
# - Depth 0: microsoft.com (seed)
# - Depth 1: azure.com, office.com (from cert SANs)
# - Depth 2: portal.azure.com, login.microsoftonline.com (subdomains)
# - Depth 3: SKIPPED (exceeds max-depth)
```

**Test 4: Multi-Source Validation**
```bash
# Run with multiple discovery modules
./shells example.com --enable-subfinder --enable-certs --enable-httpx

# Expected:
# - Assets discovered by multiple sources have higher confidence
# - Log output shows: "Asset seen from additional source"
# - Final asset list includes Sources: ["subfinder", "crt.sh", "httpx"]
```

---

## Part 6: Rollback Plan

If critical issues arise during implementation:

**Rollback Step 1**: Revert EnhancedCertificateClient wiring
```bash
git diff pkg/correlation/default_clients.go
git checkout pkg/correlation/default_clients.go
```

**Rollback Step 2**: Revert client initialization
```bash
git checkout internal/discovery/asset_relationship_mapper.go
```

**Rollback Step 3**: Disable AssetRelationshipMapping
```yaml
# .shells.yaml
enable_asset_relationship_mapping: false
```

**Safe mode**: Run with minimal discovery
```bash
./shells target.com --no-relationship-mapping --no-recursive-discovery
```

---

## Part 7: Success Metrics

### Quantitative Metrics

**Before Fixes**:
- microsoft.com discovery: 1-5 domains (only basic subdomain enum)
- Certificate lookups: 0% success rate (crt.sh 503 errors)
- Organization correlation: 0% (clients are nil)
- Confidence scoring: Not implemented
- Average assets per scan: ~10

**After Fixes (Target)**:
- microsoft.com discovery: 50-100+ domains (cert SANs + org pivot)
- Certificate lookups: 95%+ success rate (direct TLS fallback)
- Organization correlation: 100% (clients initialized)
- Confidence scoring: All assets have scores (0.0-1.0)
- Average assets per scan: 50-200 (depends on org size)

### Qualitative Metrics

**Before**:
- "shells microsoft.com" finds microsoft.com and maybe www.microsoft.com
- No azure.com, no office.com, no live.com
- Silent failures (clients are nil, no errors logged)

**After**:
- "shells microsoft.com" finds microsoft.com, azure.com, office.com, live.com, outlook.com, skype.com, xbox.com, onedrive.com, teams.microsoft.com, + 40 more
- Discovers related domains via certificate SANs, organization correlation, and ASN expansion
- All discoveries logged with confidence scores and source attribution

---

## Part 8: Documentation Updates

After implementation, update these files:

1. **README.md**: Add examples showing organization-wide discovery
2. **CLAUDE.md**: Update with new architecture patterns
3. **ROADMAP.md**: Mark completed features, add future enhancements
4. **API.md** (new): Document confidence scoring, depth tracking, source attribution

---

## Conclusion

This plan provides a **systematic approach** to fixing the intelligence loop and enabling the microsoft.com → azure.com → office.com discovery chain.

**Priorities**:
1. **Week 1**: Fix critical issues (P0) - get basic discovery working
2. **Week 2**: Add confidence scoring and depth tracking (P1)
3. **Week 3-4**: Polish and optimize (P2)

**Risk mitigation**:
- Each fix is isolated and testable
- Rollback plan if issues arise
- Incremental delivery (can stop after Week 1 if needed)

**Expected outcome**:
After Week 1, `shells microsoft.com` will discover 50+ Microsoft domains automatically, enabling comprehensive security testing of the entire organization attack surface.
