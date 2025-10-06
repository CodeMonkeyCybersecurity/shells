package progress

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// Tracker provides simple progress tracking for multi-phase operations
type Tracker struct {
	phases       []Phase
	currentPhase int
	startTime    time.Time
	mu           sync.Mutex
	enabled      bool
	logger       *logger.Logger
}

// Phase represents a single phase of work
type Phase struct {
	Name        string
	Description string
	Status      PhaseStatus
	StartTime   time.Time
	EndTime     time.Time
	Progress    int // 0-100 percentage
}

// PhaseStatus represents the status of a phase
type PhaseStatus int

const (
	StatusPending PhaseStatus = iota
	StatusRunning
	StatusCompleted
	StatusFailed
)

// New creates a new progress tracker
func New(enabled bool, log *logger.Logger) *Tracker {
	return &Tracker{
		phases:       []Phase{},
		currentPhase: 0,
		startTime:    time.Now(),
		enabled:      enabled,
		logger:       log,
	}
}

// AddPhase adds a new phase to track
func (t *Tracker) AddPhase(name, description string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.phases = append(t.phases, Phase{
		Name:        name,
		Description: description,
		Status:      StatusPending,
		Progress:    0,
	})
}

// StartPhase marks a phase as started
func (t *Tracker) StartPhase(name string) {
	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for i, phase := range t.phases {
		if phase.Name == name {
			t.phases[i].Status = StatusRunning
			t.phases[i].StartTime = time.Now()
			t.currentPhase = i
			t.render()
			return
		}
	}
}

// UpdateProgress updates the progress percentage of current phase
func (t *Tracker) UpdateProgress(name string, progress int) {
	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for i, phase := range t.phases {
		if phase.Name == name {
			t.phases[i].Progress = progress
			t.render()
			return
		}
	}
}

// CompletePhase marks a phase as completed
func (t *Tracker) CompletePhase(name string) {
	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for i, phase := range t.phases {
		if phase.Name == name {
			t.phases[i].Status = StatusCompleted
			t.phases[i].EndTime = time.Now()
			t.phases[i].Progress = 100
			t.render()
			return
		}
	}
}

// FailPhase marks a phase as failed
func (t *Tracker) FailPhase(name string, err error) {
	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for i, phase := range t.phases {
		if phase.Name == name {
			t.phases[i].Status = StatusFailed
			t.phases[i].EndTime = time.Now()
			t.render()
			if t.logger != nil {
				t.logger.Errorw("❌ Phase failed", "error", err, "phase", name, "component", "progress")
			}
			return
		}
	}
}

// render displays the current progress state
func (t *Tracker) render() {
	if !t.enabled {
		return
	}

	totalPhases := len(t.phases)
	completedPhases := 0
	for _, phase := range t.phases {
		if phase.Status == StatusCompleted {
			completedPhases++
		}
	}

	// Calculate overall progress
	overallProgress := 0
	if totalPhases > 0 {
		overallProgress = (completedPhases * 100) / totalPhases

		// Add current phase progress
		if t.currentPhase < len(t.phases) && t.phases[t.currentPhase].Status == StatusRunning {
			phaseContribution := t.phases[t.currentPhase].Progress / totalPhases
			overallProgress += phaseContribution
		}
	}

	// Render progress bar
	barWidth := 30
	filled := (overallProgress * barWidth) / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// Current phase info
	currentPhaseInfo := ""
	currentPhaseName := ""
	if t.currentPhase < len(t.phases) {
		phase := t.phases[t.currentPhase]
		currentPhaseInfo = fmt.Sprintf("%s (%d%%)", phase.Description, phase.Progress)
		currentPhaseName = phase.Name
	}

	// Calculate ETA
	elapsed := time.Since(t.startTime)
	eta := "calculating..."
	if overallProgress > 0 && overallProgress < 100 {
		totalEstimated := (elapsed * 100) / time.Duration(overallProgress)
		remaining := totalEstimated - elapsed
		eta = formatDuration(remaining)
	}

	// Log progress with structured fields
	if t.logger != nil {
		t.logger.Infow(fmt.Sprintf("[%s] %d%% | %s | ETA: %s", bar, overallProgress, currentPhaseInfo, eta),
			"progress_pct", overallProgress,
			"phase", currentPhaseName,
			"completed_phases", completedPhases,
			"total_phases", totalPhases,
			"eta", eta,
			"elapsed", formatDuration(elapsed),
			"component", "progress",
		)
	}
}

// Complete marks all phases as complete and shows final summary
func (t *Tracker) Complete() {
	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	elapsed := time.Since(t.startTime)

	if t.logger != nil {
		t.logger.Infow("✅ Scan completed",
			"duration", formatDuration(elapsed),
			"component", "progress",
		)

		// Show phase breakdown
		t.logger.Info("Phase Summary:", "component", "progress")
		for _, phase := range t.phases {
			status := "✅"
			if phase.Status == StatusFailed {
				status = "❌"
			} else if phase.Status == StatusPending {
				status = "⏸️"
			}

			duration := ""
			if !phase.EndTime.IsZero() {
				duration = formatDuration(phase.EndTime.Sub(phase.StartTime))
			}

			t.logger.Infow(fmt.Sprintf("  %s %s", status, phase.Name),
				"phase", phase.Name,
				"status", status,
				"duration", duration,
				"component", "progress",
			)
		}
	}
}

// formatDuration formats a duration in human-readable form
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "< 1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", hours, minutes)
}
