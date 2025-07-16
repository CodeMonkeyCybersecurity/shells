package archive

import (
	"time"
)

type ArchiveReport struct {
	Domain         string          `json:"domain"`
	URLs           []ArchivedURL   `json:"urls"`
	Secrets        []Secret        `json:"secrets"`
	AdminPanels    []AdminPanel    `json:"admin_panels"`
	SensitiveFiles []SensitiveFile `json:"sensitive_files"`
	ParameterNames []string        `json:"parameter_names"`
	Endpoints      []Endpoint      `json:"endpoints"`
	JSFiles        []JSFile        `json:"js_files"`
	Comments       []Comment       `json:"comments"`
	TotalSnapshots int             `json:"total_snapshots"`
	DateRange      DateRange       `json:"date_range"`
	Sources        []string        `json:"sources"`
}

type ArchivedURL struct {
	URL        string    `json:"url"`
	Timestamp  time.Time `json:"timestamp"`
	StatusCode int       `json:"status_code"`
	MimeType   string    `json:"mime_type"`
	Size       int64     `json:"size"`
	Source     string    `json:"source"`
}

type Secret struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	URL       string    `json:"url"`
	Context   string    `json:"context"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
}

type AdminPanel struct {
	URL        string    `json:"url"`
	Title      string    `json:"title"`
	Type       string    `json:"type"`
	Timestamp  time.Time `json:"timestamp"`
	Screenshot string    `json:"screenshot,omitempty"`
	Accessible bool      `json:"accessible"`
}

type SensitiveFile struct {
	URL       string    `json:"url"`
	Type      string    `json:"type"`
	Size      int64     `json:"size"`
	Timestamp time.Time `json:"timestamp"`
	Content   string    `json:"content,omitempty"`
	Hash      string    `json:"hash"`
}

type Endpoint struct {
	Path        string    `json:"path"`
	Method      string    `json:"method"`
	Parameters  []string  `json:"parameters"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Frequency   int       `json:"frequency"`
	Confidence  string    `json:"confidence"`
	StillExists bool      `json:"still_exists"`
}

type JSFile struct {
	URL       string    `json:"url"`
	Size      int64     `json:"size"`
	Timestamp time.Time `json:"timestamp"`
	Variables []string  `json:"variables"`
	Functions []string  `json:"functions"`
	APIs      []string  `json:"apis"`
	Secrets   []Secret  `json:"secrets"`
}

type Comment struct {
	Content   string    `json:"content"`
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
}

type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type ArchiveFinding struct {
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Context   string    `json:"context"`
}

type DeepArchiveReport struct {
	Domain         string                `json:"domain"`
	TotalSnapshots int                   `json:"total_snapshots"`
	Findings       []ArchiveFinding      `json:"findings"`
	Sources        map[string]Statistics `json:"sources"`
	Analysis       ArchiveAnalysis       `json:"analysis"`
}

type Statistics struct {
	TotalURLs      int `json:"total_urls"`
	UniqueURLs     int `json:"unique_urls"`
	SecretsFound   int `json:"secrets_found"`
	EndpointsFound int `json:"endpoints_found"`
	FilesFound     int `json:"files_found"`
}

type ArchiveAnalysis struct {
	TechnologyStack    []string           `json:"technology_stack"`
	FrameworksDetected []string           `json:"frameworks_detected"`
	DatabasesDetected  []string           `json:"databases_detected"`
	PathPatterns       []PathPattern      `json:"path_patterns"`
	ParameterPatterns  []ParameterPattern `json:"parameter_patterns"`
}

type PathPattern struct {
	Pattern   string   `json:"pattern"`
	Examples  []string `json:"examples"`
	Frequency int      `json:"frequency"`
}

type ParameterPattern struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Examples  []string `json:"examples"`
	Frequency int      `json:"frequency"`
}

type WaybackResponse struct {
	URLs [][]string `json:"urls"`
}

type CommonCrawlResponse struct {
	URLs []CommonCrawlURL `json:"urls"`
}

type CommonCrawlURL struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
	MimeType  string `json:"mime_type"`
	Size      string `json:"size"`
}

type ArchiveTodayResponse struct {
	Results []ArchiveTodayResult `json:"results"`
}

type ArchiveTodayResult struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	Title     string `json:"title"`
	Size      int64  `json:"size"`
}

type ArchiveCache struct {
	URLs     map[string]ArchivedURL `json:"urls"`
	Content  map[string]string      `json:"content"`
	Metadata map[string]interface{} `json:"metadata"`
}

type SecretPattern struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type EndpointPattern struct {
	Pattern     string `json:"pattern"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type CheckResult struct {
	Found   bool   `json:"found"`
	Details string `json:"details"`
	Content string `json:"content"`
}
