package cmd

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// ProgressTracker tracks progress of operations
type ProgressTracker struct {
	total     int
	current   int
	label     string
	startTime time.Time
	mu        sync.Mutex
	done      bool
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(label string, total int) *ProgressTracker {
	return &ProgressTracker{
		total:     total,
		current:   0,
		label:     label,
		startTime: time.Now(),
		done:      false,
	}
}

// Increment increments the progress
func (p *ProgressTracker) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return
	}

	p.current++
	p.render()
}

// SetCurrent sets the current progress
func (p *ProgressTracker) SetCurrent(current int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return
	}

	p.current = current
	p.render()
}

// Complete marks the progress as complete
func (p *ProgressTracker) Complete() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return
	}

	p.current = p.total
	p.done = true
	p.render()
	fmt.Println() // New line after completion
}

// Fail marks the progress as failed
func (p *ProgressTracker) Fail(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return
	}

	p.done = true
	fmt.Printf("\r%s %s\n",
		color.RedString("✗"),
		color.RedString("%s: %s", p.label, message))
}

// render renders the progress bar
func (p *ProgressTracker) render() {
	if p.total == 0 {
		return
	}

	percent := float64(p.current) / float64(p.total) * 100
	barWidth := 30
	filled := int(percent / 100 * float64(barWidth))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	elapsed := time.Since(p.startTime)
	eta := ""
	if p.current > 0 {
		remaining := time.Duration(float64(elapsed) / float64(p.current) * float64(p.total-p.current))
		eta = fmt.Sprintf(" ETA: %s", remaining.Round(time.Second))
	}

	// Clear line and render
	fmt.Printf("\r%-20s [%s] %3.0f%% (%d/%d)%s",
		p.label,
		bar,
		percent,
		p.current,
		p.total,
		eta)
}

// SimpleSpinner provides a simple spinner for indeterminate operations
type SimpleSpinner struct {
	label     string
	frames    []string
	current   int
	mu        sync.Mutex
	done      bool
	stopChan  chan struct{}
	startTime time.Time
}

// NewSimpleSpinner creates a new spinner
func NewSimpleSpinner(label string) *SimpleSpinner {
	return &SimpleSpinner{
		label:     label,
		frames:    []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		current:   0,
		stopChan:  make(chan struct{}),
		startTime: time.Now(),
	}
}

// Start starts the spinner
func (s *SimpleSpinner) Start() {
	go func() {
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopChan:
				return
			case <-ticker.C:
				s.mu.Lock()
				if !s.done {
					s.render()
					s.current = (s.current + 1) % len(s.frames)
				}
				s.mu.Unlock()
			}
		}
	}()
}

// Stop stops the spinner with success
func (s *SimpleSpinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.done {
		return
	}

	s.done = true
	close(s.stopChan)

	elapsed := time.Since(s.startTime)
	fmt.Printf("\r%s %s (%s)\n",
		color.GreenString("✓"),
		s.label,
		elapsed.Round(time.Millisecond))
}

// Fail stops the spinner with failure
func (s *SimpleSpinner) Fail(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.done {
		return
	}

	s.done = true
	close(s.stopChan)

	fmt.Printf("\r%s %s: %s\n",
		color.RedString("✗"),
		s.label,
		message)
}

// Update updates the spinner label
func (s *SimpleSpinner) Update(label string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.label = label
}

// render renders the spinner
func (s *SimpleSpinner) render() {
	elapsed := time.Since(s.startTime)
	fmt.Printf("\r%s %s (%s)",
		color.CyanString(s.frames[s.current]),
		s.label,
		elapsed.Round(time.Second))
}
