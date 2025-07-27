package scope

import (
	"regexp"
	"time"
)

// ScopeType represents the type of scope item
type ScopeType string

const (
	ScopeTypeDomain      ScopeType = "domain"
	ScopeTypeURL         ScopeType = "url"
	ScopeTypeIP          ScopeType = "ip"
	ScopeTypeIPRange     ScopeType = "ip_range"
	ScopeTypeApplication ScopeType = "application"
	ScopeTypeAPI         ScopeType = "api"
	ScopeTypeWildcard    ScopeType = "wildcard"
	ScopeTypeMobile      ScopeType = "mobile"
	ScopeTypeSource      ScopeType = "source_code"
	ScopeTypeExecutable  ScopeType = "executable"
	ScopeTypeHardware    ScopeType = "hardware"
	ScopeTypeOther       ScopeType = "other"
)

// ScopeStatus represents if an item is in or out of scope
type ScopeStatus string

const (
	ScopeStatusInScope    ScopeStatus = "in_scope"
	ScopeStatusOutOfScope ScopeStatus = "out_of_scope"
	ScopeStatusUnknown    ScopeStatus = "unknown"
)

// Platform represents a bug bounty platform
type Platform string

const (
	PlatformHackerOne Platform = "hackerone"
	PlatformBugcrowd  Platform = "bugcrowd"
	PlatformIntigriti Platform = "intigriti"
	PlatformYesWeHack Platform = "yeswehack"
	PlatformSynack    Platform = "synack"
	PlatformCustom    Platform = "custom"
)

// ScopeItem represents a single scope entry
type ScopeItem struct {
	ID              string            `json:"id"`
	Type            ScopeType         `json:"type"`
	Value           string            `json:"value"`
	Status          ScopeStatus       `json:"status"`
	Description     string            `json:"description,omitempty"`
	Severity        string            `json:"severity,omitempty"`
	EnvironmentType string            `json:"environment_type,omitempty"` // production, staging, dev
	MaxSeverity     string            `json:"max_severity,omitempty"`
	Restrictions    []string          `json:"restrictions,omitempty"`
	Instructions    string            `json:"instructions,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	CompiledPattern *regexp.Regexp    `json:"-"`
	LastUpdated     time.Time         `json:"last_updated"`
}

// Program represents a bug bounty program
type Program struct {
	ID                string            `json:"id"`
	Platform          Platform          `json:"platform"`
	Name              string            `json:"name"`
	Handle            string            `json:"handle"` // HackerOne/Bugcrowd handle
	URL               string            `json:"url"`
	Scope             []ScopeItem       `json:"scope"`
	OutOfScope        []ScopeItem       `json:"out_of_scope"`
	Rules             []Rule            `json:"rules"`
	TestingGuidelines string            `json:"testing_guidelines,omitempty"`
	Credentials       map[string]string `json:"credentials,omitempty"`
	VPNRequired       bool              `json:"vpn_required"`
	MaxBounty         float64           `json:"max_bounty,omitempty"`
	LastSynced        time.Time         `json:"last_synced"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	Active            bool              `json:"active"`
}

// Rule represents a program-specific rule
type Rule struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"` // rate_limit, testing_hours, auth_required, etc.
	Description string   `json:"description"`
	Value       string   `json:"value"`
	Applies     []string `json:"applies_to,omitempty"` // specific scope items this applies to
}

// ValidationResult contains the result of scope validation
type ValidationResult struct {
	Asset           string      `json:"asset"`
	Status          ScopeStatus `json:"status"`
	MatchedItem     *ScopeItem  `json:"matched_item,omitempty"`
	Program         *Program    `json:"program,omitempty"`
	Reason          string      `json:"reason,omitempty"`
	Restrictions    []string    `json:"restrictions,omitempty"`
	ApplicableRules []Rule      `json:"applicable_rules,omitempty"`
	ValidatedAt     time.Time   `json:"validated_at"`
}

// ScopeManager is the main interface for scope management
type ScopeManager interface {
	// Program management
	AddProgram(program *Program) error
	RemoveProgram(programID string) error
	GetProgram(programID string) (*Program, error)
	ListPrograms() ([]*Program, error)
	SyncProgram(programID string) error
	SyncAllPrograms() error

	// Validation
	ValidateAsset(asset string) (*ValidationResult, error)
	ValidateBatch(assets []string) ([]*ValidationResult, error)
	IsInScope(asset string) (bool, error)

	// Scope queries
	GetScopeForProgram(programID string) ([]ScopeItem, error)
	GetAllInScopeItems() ([]ScopeItem, error)
	SearchScope(query string) ([]ScopeItem, error)

	// Real-time monitoring
	StartMonitoring() error
	StopMonitoring() error
}
