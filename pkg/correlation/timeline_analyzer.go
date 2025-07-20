// pkg/correlation/timeline_analyzer.go
package correlation

import (
	"sort"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"go.uber.org/zap"
)

// TimelineAnalyzer analyzes temporal patterns in findings
type TimelineAnalyzer struct {
	logger *zap.Logger
}

// NewTimelineAnalyzer creates a new timeline analyzer
func NewTimelineAnalyzer() *TimelineAnalyzer {
	logger, _ := zap.NewProduction()
	return &TimelineAnalyzer{
		logger: logger,
	}
}

// BuildTimeline creates a timeline from findings
func (ta *TimelineAnalyzer) BuildTimeline(findings []types.Finding) []TimelineEvent {
	var events []TimelineEvent

	for _, finding := range findings {
		event := TimelineEvent{
			Timestamp:   finding.CreatedAt,
			Type:        finding.Type,
			Description: finding.Description,
			Severity:    finding.Severity,
			Source:      finding.Tool,
		}
		events = append(events, event)
	}

	// Sort by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	ta.logger.Info("Timeline built", zap.Int("events", len(events)))
	return events
}

// DetectTemporalPatterns identifies patterns across time
func (ta *TimelineAnalyzer) DetectTemporalPatterns(timeline []TimelineEvent) []TemporalPattern {
	var patterns []TemporalPattern

	// Look for burst patterns
	burstPatterns := ta.detectBurstPatterns(timeline)
	patterns = append(patterns, burstPatterns...)

	// Look for periodic patterns
	periodicPatterns := ta.detectPeriodicPatterns(timeline)
	patterns = append(patterns, periodicPatterns...)

	// Look for escalation patterns
	escalationPatterns := ta.detectEscalationPatterns(timeline)
	patterns = append(patterns, escalationPatterns...)

	ta.logger.Info("Temporal patterns detected", zap.Int("patterns", len(patterns)))
	return patterns
}

// detectBurstPatterns finds sudden spikes in activity
func (ta *TimelineAnalyzer) detectBurstPatterns(timeline []TimelineEvent) []TemporalPattern {
	var patterns []TemporalPattern

	if len(timeline) < 3 {
		return patterns
	}

	// Group events by time windows (1 hour)
	windowSize := time.Hour
	windows := make(map[int64][]TimelineEvent)

	for _, event := range timeline {
		window := event.Timestamp.Unix() / int64(windowSize.Seconds())
		windows[window] = append(windows[window], event)
	}

	// Calculate average events per window
	totalEvents := 0
	for _, events := range windows {
		totalEvents += len(events)
	}
	avgEventsPerWindow := float64(totalEvents) / float64(len(windows))

	// Find windows with significantly more events (burst threshold: 3x average)
	burstThreshold := avgEventsPerWindow * 3

	for window, events := range windows {
		if float64(len(events)) > burstThreshold {
			pattern := TemporalPattern{
				Type:        "burst",
				StartTime:   time.Unix(window*int64(windowSize.Seconds()), 0),
				EndTime:     time.Unix((window+1)*int64(windowSize.Seconds()), 0),
				EventCount:  len(events),
				Confidence:  0.8,
				Description: "Sudden burst of security events detected",
				Events:      events,
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// detectPeriodicPatterns finds recurring patterns
func (ta *TimelineAnalyzer) detectPeriodicPatterns(timeline []TimelineEvent) []TemporalPattern {
	var patterns []TemporalPattern

	if len(timeline) < 5 {
		return patterns
	}

	// Group by event type
	eventsByType := make(map[string][]TimelineEvent)
	for _, event := range timeline {
		eventsByType[event.Type] = append(eventsByType[event.Type], event)
	}

	// Look for periodic patterns in each event type
	for eventType, events := range eventsByType {
		if len(events) < 3 {
			continue
		}

		// Calculate intervals between events
		var intervals []time.Duration
		for i := 1; i < len(events); i++ {
			interval := events[i].Timestamp.Sub(events[i-1].Timestamp)
			intervals = append(intervals, interval)
		}

		// Check for consistent intervals (variance < 20%)
		if ta.isPeriodicPattern(intervals) {
			avgInterval := ta.calculateAverageInterval(intervals)
			pattern := TemporalPattern{
				Type:        "periodic",
				StartTime:   events[0].Timestamp,
				EndTime:     events[len(events)-1].Timestamp,
				EventCount:  len(events),
				Confidence:  0.7,
				Description: "Periodic pattern detected for " + eventType,
				Events:      events,
				Interval:    avgInterval,
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// detectEscalationPatterns finds security posture degradation
func (ta *TimelineAnalyzer) detectEscalationPatterns(timeline []TimelineEvent) []TemporalPattern {
	var patterns []TemporalPattern

	if len(timeline) < 3 {
		return patterns
	}

	// Look for severity escalation
	var severityTrend []int
	for _, event := range timeline {
		severityScore := ta.severityToScore(event.Severity)
		severityTrend = append(severityTrend, severityScore)
	}

	// Check for increasing severity trend
	if ta.isEscalatingTrend(severityTrend) {
		pattern := TemporalPattern{
			Type:        "escalation",
			StartTime:   timeline[0].Timestamp,
			EndTime:     timeline[len(timeline)-1].Timestamp,
			EventCount:  len(timeline),
			Confidence:  0.8,
			Description: "Security posture degradation detected - increasing severity over time",
			Events:      timeline,
		}
		patterns = append(patterns, pattern)
	}

	return patterns
}

// Helper functions

func (ta *TimelineAnalyzer) isPeriodicPattern(intervals []time.Duration) bool {
	if len(intervals) < 2 {
		return false
	}

	// Calculate average interval
	avg := ta.calculateAverageInterval(intervals)

	// Check variance
	var variance float64
	for _, interval := range intervals {
		diff := float64(interval - avg)
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	// Allow 20% variance
	threshold := float64(avg) * 0.2
	return variance < threshold*threshold
}

func (ta *TimelineAnalyzer) calculateAverageInterval(intervals []time.Duration) time.Duration {
	var total time.Duration
	for _, interval := range intervals {
		total += interval
	}
	return total / time.Duration(len(intervals))
}

func (ta *TimelineAnalyzer) severityToScore(severity types.Severity) int {
	switch severity {
	case types.SeverityInfo:
		return 1
	case types.SeverityLow:
		return 2
	case types.SeverityMedium:
		return 3
	case types.SeverityHigh:
		return 4
	case types.SeverityCritical:
		return 5
	default:
		return 0
	}
}

func (ta *TimelineAnalyzer) isEscalatingTrend(scores []int) bool {
	if len(scores) < 3 {
		return false
	}

	// Count how many times severity increases vs decreases
	increases := 0
	decreases := 0

	for i := 1; i < len(scores); i++ {
		if scores[i] > scores[i-1] {
			increases++
		} else if scores[i] < scores[i-1] {
			decreases++
		}
	}

	// Consider it escalating if increases outnumber decreases by 2:1
	return increases > decreases*2
}

// TemporalPattern represents a pattern found in the timeline
type TemporalPattern struct {
	Type        string
	StartTime   time.Time
	EndTime     time.Time
	EventCount  int
	Confidence  float64
	Description string
	Events      []TimelineEvent
	Interval    time.Duration // For periodic patterns
}