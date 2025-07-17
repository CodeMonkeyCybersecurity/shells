package core

import (
	"context"
	"io"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type Scanner interface {
	Name() string
	Type() types.ScanType
	Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error)
	Validate(target string) error
}

type JobQueue interface {
	Push(ctx context.Context, job *types.Job) error
	Pop(ctx context.Context, workerID string) (*types.Job, error)
	Complete(ctx context.Context, jobID string) error
	Fail(ctx context.Context, jobID string, reason string) error
	Retry(ctx context.Context, jobID string) error
	GetStatus(ctx context.Context, jobID string) (*types.Job, error)
	GetPending(ctx context.Context) ([]*types.Job, error)
	Close() error
}

type ResultStore interface {
	SaveScan(ctx context.Context, scan *types.ScanRequest) error
	UpdateScan(ctx context.Context, scan *types.ScanRequest) error
	GetScan(ctx context.Context, scanID string) (*types.ScanRequest, error)
	ListScans(ctx context.Context, filter ScanFilter) ([]*types.ScanRequest, error)

	SaveFindings(ctx context.Context, findings []types.Finding) error
	GetFindings(ctx context.Context, scanID string) ([]types.Finding, error)
	GetFindingsBySeverity(ctx context.Context, severity types.Severity) ([]types.Finding, error)
	
	// Enhanced query methods
	QueryFindings(ctx context.Context, query FindingQuery) ([]types.Finding, error)
	GetFindingStats(ctx context.Context) (*FindingStats, error)
	GetRecentCriticalFindings(ctx context.Context, limit int) ([]types.Finding, error)
	SearchFindings(ctx context.Context, searchTerm string, limit int) ([]types.Finding, error)

	GetSummary(ctx context.Context, scanID string) (*types.Summary, error)
	Close() error
}

type ScanFilter struct {
	Target   string
	Status   types.ScanStatus
	Type     types.ScanType
	FromDate *string
	ToDate   *string
	Limit    int
	Offset   int
}

type FindingQuery struct {
	ScanID     string
	Tool       string
	Type       string
	Severity   string
	Target     string
	SearchTerm string
	FromDate   *time.Time
	ToDate     *time.Time
	OrderBy    string
	Limit      int
	Offset     int
}

type FindingStats struct {
	Total      int
	BySeverity map[types.Severity]int
	ByTool     map[string]int
	ByType     map[string]int
	ByTarget   map[string]int
}

type Worker interface {
	ID() string
	Start(ctx context.Context) error
	Stop() error
	Status() *types.WorkerStatus
}

type WorkerPool interface {
	Start(ctx context.Context, workers int) error
	Stop() error
	Scale(workers int) error
	Status() []*types.WorkerStatus
}

type Exporter interface {
	Name() string
	Export(findings []types.Finding, writer io.Writer) error
	FileExtension() string
}

type RateLimiter interface {
	Wait(ctx context.Context, target string) error
	SetLimit(target string, requestsPerSecond int)
}

type ScopeValidator interface {
	IsInScope(target string) bool
	AddToScope(pattern string) error
	RemoveFromScope(pattern string) error
	ListScope() []string
}

type PluginManager interface {
	Register(scanner Scanner) error
	Get(name string) (Scanner, error)
	List() []string
}

type Telemetry interface {
	RecordScan(scanType types.ScanType, duration float64, success bool)
	RecordFinding(severity types.Severity)
	RecordWorkerMetrics(status *types.WorkerStatus)
	Close() error
}
