package orchestrator

import (
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/discovery"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/correlation"
	"github.com/CodeMonkeyCybersecurity/artemis/pkg/types"
)

// BugBountyResult contains the complete results of a bug bounty scan
// Thread-safe: All mutations protected by mutexes to prevent race conditions
type BugBountyResult struct {
	// Basic metadata (read-only after creation, no mutex needed)
	ScanID    string
	Target    string
	StartTime time.Time

	// Mutable fields protected by resultMutex
	EndTime       time.Time
	Duration      time.Duration
	Status        string
	DiscoveredAt  int // Number of discovered assets
	TestedAssets  int
	TotalFindings int
	resultMutex   sync.RWMutex

	// Organization and discovery metadata (write-once, then read-only)
	OrganizationInfo *correlation.Organization
	DiscoverySession *discovery.DiscoverySession
	metadataMutex    sync.RWMutex

	// Collections that can be mutated concurrently (each protected separately)
	Findings      []types.Finding
	findingsMutex sync.RWMutex // P0-19: Protects Findings from race conditions

	PhaseResults      map[string]PhaseResult
	phaseResultsMutex sync.RWMutex // P0-20: Protects PhaseResults map from concurrent writes

	DiscoveredAssets []*discovery.Asset
	assetsMutex      sync.RWMutex // P0-2: Protects DiscoveredAssets from race conditions
}

// PhaseResult contains results from a specific phase
type PhaseResult struct {
	Phase     string
	Status    string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Findings  int
	Error     string
}

// NewBugBountyResult creates a new thread-safe result container
func NewBugBountyResult(scanID, target string, startTime time.Time) *BugBountyResult {
	return &BugBountyResult{
		ScanID:           scanID,
		Target:           target,
		StartTime:        startTime,
		Status:           "running",
		PhaseResults:     make(map[string]PhaseResult),
		Findings:         []types.Finding{},
		DiscoveredAssets: []*discovery.Asset{},
	}
}

// Thread-safe getters and setters for basic fields

func (r *BugBountyResult) SetEndTime(t time.Time) {
	r.resultMutex.Lock()
	defer r.resultMutex.Unlock()
	r.EndTime = t
}

func (r *BugBountyResult) SetDuration(d time.Duration) {
	r.resultMutex.Lock()
	defer r.resultMutex.Unlock()
	r.Duration = d
}

func (r *BugBountyResult) SetStatus(status string) {
	r.resultMutex.Lock()
	defer r.resultMutex.Unlock()
	r.Status = status
}

func (r *BugBountyResult) SetDiscoveredAt(count int) {
	r.resultMutex.Lock()
	defer r.resultMutex.Unlock()
	r.DiscoveredAt = count
}

func (r *BugBountyResult) SetTestedAssets(count int) {
	r.resultMutex.Lock()
	defer r.resultMutex.Unlock()
	r.TestedAssets = count
}

func (r *BugBountyResult) SetTotalFindings(count int) {
	r.resultMutex.Lock()
	defer r.resultMutex.Unlock()
	r.TotalFindings = count
}

// Thread-safe metadata operations

func (r *BugBountyResult) SetOrganizationInfo(org *correlation.Organization) {
	r.metadataMutex.Lock()
	defer r.metadataMutex.Unlock()
	r.OrganizationInfo = org
}

func (r *BugBountyResult) GetOrganizationInfo() *correlation.Organization {
	r.metadataMutex.RLock()
	defer r.metadataMutex.RUnlock()
	return r.OrganizationInfo
}

func (r *BugBountyResult) SetDiscoverySession(session *discovery.DiscoverySession) {
	r.metadataMutex.Lock()
	defer r.metadataMutex.Unlock()
	r.DiscoverySession = session
}

func (r *BugBountyResult) GetDiscoverySession() *discovery.DiscoverySession {
	r.metadataMutex.RLock()
	defer r.metadataMutex.RUnlock()
	return r.DiscoverySession
}

// P0-19 FIX: Thread-safe findings operations

// AddFinding adds a single finding thread-safely
func (r *BugBountyResult) AddFinding(finding types.Finding) {
	r.findingsMutex.Lock()
	defer r.findingsMutex.Unlock()
	r.Findings = append(r.Findings, finding)
}

// AddFindings adds multiple findings thread-safely
func (r *BugBountyResult) AddFindings(findings []types.Finding) {
	r.findingsMutex.Lock()
	defer r.findingsMutex.Unlock()
	r.Findings = append(r.Findings, findings...)
}

// GetFindings returns a copy of findings (safe for reading)
func (r *BugBountyResult) GetFindings() []types.Finding {
	r.findingsMutex.RLock()
	defer r.findingsMutex.RUnlock()
	// Return copy to prevent external mutation
	findings := make([]types.Finding, len(r.Findings))
	copy(findings, r.Findings)
	return findings
}

// GetFindingsForCheckpoint returns findings slice for checkpoint save (read lock held)
// Caller must not mutate the returned slice
func (r *BugBountyResult) GetFindingsForCheckpoint() []types.Finding {
	r.findingsMutex.RLock()
	defer r.findingsMutex.RUnlock()
	return r.Findings
}

// P0-20 FIX: Thread-safe phase results operations

// SetPhaseResult sets a phase result thread-safely
func (r *BugBountyResult) SetPhaseResult(phase string, result PhaseResult) {
	r.phaseResultsMutex.Lock()
	defer r.phaseResultsMutex.Unlock()
	r.PhaseResults[phase] = result
}

// GetPhaseResult gets a phase result thread-safely
func (r *BugBountyResult) GetPhaseResult(phase string) (PhaseResult, bool) {
	r.phaseResultsMutex.RLock()
	defer r.phaseResultsMutex.RUnlock()
	result, ok := r.PhaseResults[phase]
	return result, ok
}

// GetAllPhaseResults returns a copy of all phase results
func (r *BugBountyResult) GetAllPhaseResults() map[string]PhaseResult {
	r.phaseResultsMutex.RLock()
	defer r.phaseResultsMutex.RUnlock()
	results := make(map[string]PhaseResult, len(r.PhaseResults))
	for k, v := range r.PhaseResults {
		results[k] = v
	}
	return results
}

// P0-2 FIX: Thread-safe asset operations

// SetDiscoveredAssets sets the discovered assets thread-safely
func (r *BugBountyResult) SetDiscoveredAssets(assets []*discovery.Asset) {
	r.assetsMutex.Lock()
	defer r.assetsMutex.Unlock()
	r.DiscoveredAssets = assets
}

// GetDiscoveredAssets returns the discovered assets thread-safely
func (r *BugBountyResult) GetDiscoveredAssets() []*discovery.Asset {
	r.assetsMutex.RLock()
	defer r.assetsMutex.RUnlock()
	return r.DiscoveredAssets
}

// GetDiscoveredAssetsForCheckpoint returns assets for checkpoint save (read lock held)
func (r *BugBountyResult) GetDiscoveredAssetsForCheckpoint() []*discovery.Asset {
	r.assetsMutex.RLock()
	defer r.assetsMutex.RUnlock()
	return r.DiscoveredAssets
}
