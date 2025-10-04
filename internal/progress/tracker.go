package progress

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Tracker provides simple progress tracking for multi-phase operations
type Tracker struct {
	phases       []Phase
	currentPhase int
	startTime    time.Time
	mu           sync.Mutex
	enabled      bool
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
func New(enabled bool) *Tracker {
	return &Tracker{
		phases:       []Phase{},
		currentPhase: 0,
		startTime:    time.Now(),
		enabled:      enabled,
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
			fmt.Printf("\n❌ Phase failed: %v\n", err)
			return
		}
	}
}

// render displays the current progress state
func (t *Tracker) render() {
	if !t.enabled {
		return
	}

	// Clear previous lines (simple version - just print newline)
	fmt.Print("\r\033[K") // Clear current line

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
	if t.currentPhase < len(t.phases) {
		phase := t.phases[t.currentPhase]
		currentPhaseInfo = fmt.Sprintf("%s (%d%%)", phase.Description, phase.Progress)
	}

	// Calculate ETA
	elapsed := time.Since(t.startTime)
	eta := "calculating..."
	if overallProgress > 0 && overallProgress < 100 {
		totalEstimated := (elapsed * 100) / time.Duration(overallProgress)
		remaining := totalEstimated - elapsed
		eta = formatDuration(remaining)
	}

	// Print progress line
	fmt.Printf("[%s] %d%% | %s | ETA: %s",
		bar,
		overallProgress,
		currentPhaseInfo,
		eta,
	)
}

// Complete marks all phases as complete and shows final summary
func (t *Tracker) Complete() {
	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	fmt.Print("\r\033[K") // Clear current line

	elapsed := time.Since(t.startTime)

	fmt.Printf("\n✅ Scan completed in %s\n\n", formatDuration(elapsed))

	// Show phase breakdown
	fmt.Println("Phase Summary:")
	for _, phase := range t.phases {
		status := "✅"
		if phase.Status == StatusFailed {
			status = "❌"
		} else if phase.Status == StatusPending {
			status = "⏸️"
		}

		duration := ""
		if !phase.EndTime.IsZero() {
			duration = fmt.Sprintf(" (%s)", formatDuration(phase.EndTime.Sub(phase.StartTime)))
		}

		fmt.Printf("  %s %s%s\n", status, phase.Name, duration)
	}
	fmt.Println()
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
