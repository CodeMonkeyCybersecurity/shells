package boileau

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/nomad"
)

// Executor handles the execution of boileau tools
type Executor struct {
	config      Config
	logger      Logger
	nomadClient *nomad.Client
	parsers     map[string]OutputParser
}

// OutputParser parses tool output into findings
type OutputParser interface {
	Parse(output string) ([]ToolFinding, error)
}

// NewExecutor creates a new tool executor
func NewExecutor(config Config, logger Logger) *Executor {
	e := &Executor{
		config:  config,
		logger:  logger,
		parsers: make(map[string]OutputParser),
	}

	// Initialize Nomad client if needed
	if config.UseNomad {
		e.nomadClient = nomad.NewClient("")
	}

	// Initialize parsers for each tool
	e.initializeParsers()

	return e
}

// initializeParsers sets up output parsers for each tool
func (e *Executor) initializeParsers() {
	// Create parser instances
	e.parsers["xsstrike"] = NewXSSStrikeParser()
	e.parsers["sqlmap"] = NewSQLMapParser()
	e.parsers["masscan"] = NewMasscanParser()
	e.parsers["aquatone"] = NewAquatoneParser()
	e.parsers["tplmap"] = NewTplmapParser()
	e.parsers["ssrfmap"] = NewSSRFMapParser()
	e.parsers["nosqlmap"] = NewNoSQLMapParser()
	e.parsers["corscanner"] = NewCORSScannerParser()
	e.parsers["commix"] = NewCommixParser()
	e.parsers["arjun"] = NewArjunParser()
	e.parsers["gopherus"] = NewGopherusParser()
}

// Execute runs a tool and returns the result
func (e *Executor) Execute(ctx context.Context, toolName, target string, options map[string]string) (*ToolResult, error) {
	result := &ToolResult{
		Tool:      toolName,
		Target:    target,
		StartTime: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Choose execution method
	var output string
	var err error

	if e.config.UseNomad && e.nomadClient != nil && e.nomadClient.IsAvailable() {
		output, err = e.executeNomad(ctx, toolName, target, options)
	} else if e.config.UseDocker {
		output, err = e.executeDocker(ctx, toolName, target, options)
	} else {
		output, err = e.executeLocal(ctx, toolName, target, options)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	result.Success = true
	result.Output = output

	// Parse output for findings
	if parser, ok := e.parsers[toolName]; ok {
		findings, parseErr := parser.Parse(output)
		if parseErr != nil {
			e.logger.Warn("Failed to parse tool output", "tool", toolName, "error", parseErr)
		} else {
			result.Findings = findings
		}
	}

	return result, nil
}

// executeDocker runs a tool in a Docker container
func (e *Executor) executeDocker(ctx context.Context, toolName, target string, options map[string]string) (string, error) {
	imageName := e.config.DockerImages[toolName]
	if imageName == "" {
		return "", fmt.Errorf("no Docker image configured for tool: %s", toolName)
	}

	// Build docker command
	args := []string{"run", "--rm"}

	// Add volume mount for output
	if outputDir, ok := options["output_dir"]; ok {
		absPath, _ := filepath.Abs(outputDir)
		args = append(args, "-v", fmt.Sprintf("%s:/output", absPath))
	}

	// Add environment variables
	args = append(args, "-e", fmt.Sprintf("TARGET=%s", target))

	// Add tool-specific options
	args = append(args, e.getDockerOptions(toolName, options)...)

	// Add image name
	args = append(args, imageName)

	// Add tool command
	args = append(args, e.getToolCommand(toolName, target, options)...)

	e.logger.Debug("Executing Docker command", "command", "docker", "args", args)

	// Execute
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("docker execution failed: %w\nstderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// executeNomad runs a tool as a Nomad job
func (e *Executor) executeNomad(ctx context.Context, toolName, target string, options map[string]string) (string, error) {
	// Create job metadata
	meta := map[string]string{
		"tool":   toolName,
		"target": target,
	}
	for k, v := range options {
		meta[k] = v
	}

	// Submit job
	jobID, err := e.nomadClient.SubmitScan(ctx, "boileau", target, fmt.Sprintf("boileau-%s", toolName), options)
	if err != nil {
		return "", fmt.Errorf("failed to submit Nomad job: %w", err)
	}

	// Wait for completion
	_, err = e.nomadClient.WaitForCompletion(ctx, jobID, e.config.Timeout)
	if err != nil {
		return "", fmt.Errorf("job execution failed: %w", err)
	}

	// Get logs
	logs, err := e.nomadClient.GetJobLogs(ctx, jobID)
	if err != nil {
		return "", fmt.Errorf("failed to get job logs: %w", err)
	}

	return logs, nil
}

// executeLocal runs a tool locally (not implemented for security tools)
func (e *Executor) executeLocal(ctx context.Context, toolName, target string, options map[string]string) (string, error) {
	return "", fmt.Errorf("local execution not supported for %s - use Docker or Nomad", toolName)
}

// getDockerOptions returns Docker-specific options for a tool
func (e *Executor) getDockerOptions(toolName string, options map[string]string) []string {
	var args []string

	switch toolName {
	case "masscan":
		// Masscan needs network privileges
		args = append(args, "--cap-add=NET_ADMIN", "--cap-add=NET_RAW")
	case "aquatone":
		// Aquatone needs display for screenshots
		args = append(args, "-e", "DISPLAY=:99")
	}

	return args
}

// getToolCommand builds the command line for a specific tool
func (e *Executor) getToolCommand(toolName, target string, options map[string]string) []string {
	switch toolName {
	case "xsstrike":
		return e.buildXSSStrikeCommand(target, options)
	case "sqlmap":
		return e.buildSQLMapCommand(target, options)
	case "masscan":
		return e.buildMasscanCommand(target, options)
	case "aquatone":
		return e.buildAquatoneCommand(target, options)
	case "tplmap":
		return e.buildTplmapCommand(target, options)
	case "ssrfmap":
		return e.buildSSRFMapCommand(target, options)
	case "nosqlmap":
		return e.buildNoSQLMapCommand(target, options)
	case "corscanner":
		return e.buildCORSScannerCommand(target, options)
	case "commix":
		return e.buildCommixCommand(target, options)
	case "arjun":
		return e.buildArjunCommand(target, options)
	case "gopherus":
		return e.buildGopherusCommand(target, options)
	default:
		return []string{}
	}
}

// Tool-specific command builders

func (e *Executor) buildXSSStrikeCommand(target string, options map[string]string) []string {
	args := []string{"python", "xsstrike.py", "-u", target}
	
	if options["crawl"] == "true" {
		args = append(args, "--crawl")
	}
	if cookie := options["cookie"]; cookie != "" {
		args = append(args, "--cookie", cookie)
	}
	
	return args
}

func (e *Executor) buildSQLMapCommand(target string, options map[string]string) []string {
	args := []string{"python", "sqlmap.py", "-u", target, "--batch"}
	
	if data := options["data"]; data != "" {
		args = append(args, "--data", data)
	}
	if cookie := options["cookie"]; cookie != "" {
		args = append(args, "--cookie", cookie)
	}
	if method := options["method"]; method != "" {
		args = append(args, "--method", method)
	}
	
	return args
}

func (e *Executor) buildMasscanCommand(target string, options map[string]string) []string {
	args := []string{"masscan", target}
	
	if ports := options["ports"]; ports != "" {
		args = append(args, "-p", ports)
	} else {
		args = append(args, "-p", "1-65535")
	}
	
	if rate := options["rate"]; rate != "" {
		args = append(args, "--rate", rate)
	} else {
		args = append(args, "--rate", "1000")
	}
	
	args = append(args, "--open-only")
	return args
}

func (e *Executor) buildAquatoneCommand(target string, options map[string]string) []string {
	args := []string{"aquatone"}
	
	if ports := options["ports"]; ports != "" {
		args = append(args, "-ports", ports)
	}
	
	args = append(args, "-out", "/output")
	return args
}

func (e *Executor) buildTplmapCommand(target string, options map[string]string) []string {
	args := []string{"python", "tplmap.py", "-u", target}
	
	if data := options["data"]; data != "" {
		args = append(args, "--data", data)
	}
	
	return args
}

func (e *Executor) buildSSRFMapCommand(target string, options map[string]string) []string {
	args := []string{"python", "ssrfmap.py", "-u", target}
	
	if data := options["data"]; data != "" {
		args = append(args, "--data", data)
	}
	
	return args
}

func (e *Executor) buildNoSQLMapCommand(target string, options map[string]string) []string {
	args := []string{"python", "nosqlmap.py", "-u", target}
	
	if cookie := options["cookie"]; cookie != "" {
		args = append(args, "--cookie", cookie)
	}
	
	return args
}

func (e *Executor) buildCORSScannerCommand(target string, options map[string]string) []string {
	return []string{"python", "cors-scanner.py", "-u", target}
}

func (e *Executor) buildCommixCommand(target string, options map[string]string) []string {
	args := []string{"python", "commix.py", "-u", target}
	
	if data := options["data"]; data != "" {
		args = append(args, "--data", data)
	}
	
	return args
}

func (e *Executor) buildArjunCommand(target string, options map[string]string) []string {
	return []string{"arjun", "-u", target}
}

func (e *Executor) buildGopherusCommand(target string, options map[string]string) []string {
	return []string{"gopherus", "--exploit", target}
}

// SaveJSON saves data as JSON to a file
func SaveJSON(outputDir, filename string, data interface{}) error {
	// Implementation would marshal to JSON and save
	// For now, just create the directory
	return os.MkdirAll(outputDir, 0755)
}