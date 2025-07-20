package boileau

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
)

// Scanner manages heavy boileau security tools
type Scanner struct {
	config    Config
	logger    Logger
	executor  *Executor
	converter *ResultConverter
}

// NewScanner creates a new boileau scanner
func NewScanner(config Config, logger Logger) *Scanner {
	// Set default docker images if not provided
	if config.DockerImages == nil {
		config.DockerImages = map[string]string{
			"aquatone":   "michenriksen/aquatone:latest",
			"masscan":    "robertdavidgraham/masscan:latest",
			"xsstrike":   "omespino/xsstrike:latest",
			"sqlmap":     "owasp/sqlmap:latest",
			"tplmap":     "cytopia/tplmap:latest",
			"ssrfmap":    "swisskyrepo/ssrfmap:latest",
			"nosqlmap":   "charliecampbell/nosqlmap:latest",
			"corscanner": "we45/corscanner:latest",
			"commix":     "stasinopoulos/commix:latest",
			"arjun":      "knassar702/arjun:latest",
			"gopherus":   "tarunkoyalwar/gopherus:latest",
		}
	}

	// Set default max concurrency
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 3
	}

	return &Scanner{
		config:    config,
		logger:    logger,
		executor:  NewExecutor(config, logger),
		converter: NewResultConverter(),
	}
}

// RunTool runs a single boileau tool
func (s *Scanner) RunTool(ctx context.Context, toolName, target string, options map[string]string) (*ToolResult, error) {
	s.logger.Info("Running boileau tool", "tool", toolName, "target", target)

	// Validate tool name
	if !s.isValidTool(toolName) {
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}

	// Execute tool
	result, err := s.executor.Execute(ctx, toolName, target, options)
	if err != nil {
		s.logger.Error("Tool execution failed", "tool", toolName, "error", err)
		return &ToolResult{
			Tool:      toolName,
			Target:    target,
			Success:   false,
			StartTime: time.Now(),
			EndTime:   time.Now(),
			Error:     err.Error(),
		}, err
	}

	s.logger.Info("Tool execution completed",
		"tool", toolName,
		"success", result.Success,
		"findings", len(result.Findings),
		"duration", result.Duration)

	return result, nil
}

// RunMultipleTools runs multiple tools with concurrency control
func (s *Scanner) RunMultipleTools(ctx context.Context, tools []string, target string, options map[string]string) ([]*ToolResult, error) {
	s.logger.Info("Running multiple boileau tools", "tools", tools, "target", target)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.config.MaxConcurrency)
	resultsChan := make(chan *ToolResult, len(tools))

	for _, tool := range tools {
		wg.Add(1)
		go func(toolName string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Check context
			select {
			case <-ctx.Done():
				resultsChan <- &ToolResult{
					Tool:    toolName,
					Target:  target,
					Success: false,
					Error:   "context cancelled",
				}
				return
			default:
			}

			// Run tool
			result, err := s.RunTool(ctx, toolName, target, options)
			if err != nil {
				s.logger.Error("Tool failed in batch", "tool", toolName, "error", err)
			}
			resultsChan <- result
		}(tool)
	}

	// Wait for all tools to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	var results []*ToolResult
	for result := range resultsChan {
		results = append(results, result)
	}

	s.logger.Info("Batch execution completed", "total_tools", len(tools), "results", len(results))
	return results, nil
}

// GetAvailableTools returns a map of available tools and their types
func (s *Scanner) GetAvailableTools() map[string]string {
	return map[string]string{
		"aquatone":   ToolTypeVisualRecon,
		"masscan":    ToolTypePortScanner,
		"xsstrike":   ToolTypeXSSScanner,
		"tplmap":     ToolTypeTemplateInjection,
		"gopherus":   ToolTypeSSRFExploitation,
		"ssrfmap":    ToolTypeSSRFScanner,
		"nosqlmap":   ToolTypeNoSQLInjection,
		"corscanner": ToolTypeCORSMisconfig,
		"sqlmap":     ToolTypeSQLInjection,
		"commix":     ToolTypeCommandInjection,
		"arjun":      ToolTypeParameterDiscovery,
	}
}

// ConvertToFindings converts tool results to standard findings
func (s *Scanner) ConvertToFindings(results []*ToolResult) []types.Finding {
	return s.converter.ConvertResults(results)
}

// isValidTool checks if a tool name is valid
func (s *Scanner) isValidTool(toolName string) bool {
	tools := s.GetAvailableTools()
	_, exists := tools[toolName]
	return exists
}

// ResultConverter converts boileau tool results to standard findings
type ResultConverter struct{}

// NewResultConverter creates a new result converter
func NewResultConverter() *ResultConverter {
	return &ResultConverter{}
}

// ConvertResults converts multiple tool results to standard findings
func (c *ResultConverter) ConvertResults(results []*ToolResult) []types.Finding {
	var findings []types.Finding

	for _, result := range results {
		if result.Success && len(result.Findings) > 0 {
			for _, toolFinding := range result.Findings {
				finding := c.convertFinding(result.Tool, result.Target, toolFinding)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// convertFinding converts a single tool finding to a standard finding
func (c *ResultConverter) convertFinding(tool, target string, toolFinding ToolFinding) types.Finding {
	return types.Finding{
		ID:          uuid.New().String(),
		Tool:        fmt.Sprintf("boileau-%s", tool),
		Type:        toolFinding.Type,
		Severity:    c.convertSeverity(toolFinding.Severity),
		Title:       toolFinding.Title,
		Description: toolFinding.Description,
		Evidence:    toolFinding.Evidence,
		Solution:    toolFinding.Solution,
		References:  toolFinding.References,
		Metadata: map[string]interface{}{
			"boileau_tool":  tool,
			"target":        target,
			"tool_metadata": toolFinding.Metadata,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// convertSeverity converts boileau severity to types.Severity
func (c *ResultConverter) convertSeverity(severity string) types.Severity {
	switch severity {
	case SeverityCritical:
		return types.SeverityCritical
	case SeverityHigh:
		return types.SeverityHigh
	case SeverityMedium:
		return types.SeverityMedium
	case SeverityLow:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
