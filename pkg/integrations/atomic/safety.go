package atomic

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SafetyFilter ensures only safe tests are executed in bug bounty context
type SafetyFilter struct {
	allowedTechniques []string
	blockedCommands   []string
	blockedPaths      []string
	maxExecutionTime  time.Duration
	safetyRules       []SafetyRule
}

// NewSafetyFilter creates a new safety filter with bug bounty constraints
func NewSafetyFilter() *SafetyFilter {
	return &SafetyFilter{
		allowedTechniques: BugBountySafeTechniques,
		blockedCommands:   BlockedCommands,
		blockedPaths:      BlockedPaths,
		maxExecutionTime:  30 * time.Second,
		safetyRules:       DefaultSafetyRules,
	}
}

// ONLY these ATT&CK techniques are safe for bug bounties
var BugBountySafeTechniques = []string{
	// Discovery (read-only)
	"T1087",    // Account Discovery
	"T1087.001", // Local Account Discovery
	"T1087.002", // Domain Account Discovery
	"T1083",    // File and Directory Discovery
	"T1057",    // Process Discovery
	"T1012",    // Query Registry
	"T1018",    // Remote System Discovery
	"T1069",    // Permission Groups Discovery
	"T1082",    // System Information Discovery
	"T1016",    // System Network Configuration Discovery
	"T1033",    // System Owner/User Discovery
	"T1007",    // System Service Discovery
	"T1049",    // System Network Connections Discovery
	"T1124",    // System Time Discovery
	"T1497",    // Virtualization/Sandbox Evasion (detection only)
	
	// Collection (read-only demonstrations)
	"T1005",    // Data from Local System (read only)
	"T1039",    // Data from Network Drives (read only)
	"T1114",    // Email Collection (detection only)
	"T1056",    // Input Capture (detection only)
	"T1113",    // Screen Capture (detection only)
	
	// Credential Access (detection/demonstration only)
	"T1003",    // OS Credential Dumping (check only)
	"T1552",    // Unsecured Credentials
	"T1552.001", // Credentials In Files
	"T1552.002", // Credentials in Registry
	"T1552.004", // Private Keys
	"T1552.005", // Cloud Instance Metadata API
	"T1552.006", // Group Policy Preferences
	"T1110",    // Brute Force (simulation only)
	"T1555",    // Credentials from Password Stores (check only)
	
	// Defense Evasion (detection only)
	"T1036",    // Masquerading (check only)
	"T1055",    // Process Injection (check only)
	"T1027",    // Obfuscated Files or Information (detection)
	"T1564",    // Hide Artifacts (detection)
	"T1070",    // Indicator Removal on Host (detection)
	
	// Initial Access (simulation/detection)
	"T1190",    // Exploit Public-Facing Application
	"T1566",    // Phishing (simulation only)
	"T1078",    // Valid Accounts (check only)
	
	// Persistence (detection only)
	"T1053",    // Scheduled Task/Job (check only)
	"T1543",    // Create or Modify System Process (detection)
	
	// Privilege Escalation (detection only)
	"T1068",    // Exploitation for Privilege Escalation (check only)
	"T1134",    // Access Token Manipulation (detection)
	
	// Lateral Movement (detection only)
	"T1021",    // Remote Services (check only)
	"T1080",    // Taint Shared Content (detection)
	
	// Command and Control (detection only)
	"T1071",    // Application Layer Protocol (detection)
	"T1090",    // Proxy (detection)
	"T1219",    // Remote Access Software (detection)
	
	// Exfiltration (simulation only)
	"T1041",    // Exfiltration Over C2 Channel (simulation)
	"T1048",    // Exfiltration Over Alternative Protocol (simulation)
	"T1567",    // Exfiltration Over Web Service (simulation)
	"T1530",    // Data from Cloud Storage Object (read-only)
}

// Commands that should NEVER run in bug bounty testing
var BlockedCommands = []string{
	// Destructive file operations
	"rm -rf", "rm -f", "del /f", "del /s", "del /q",
	"format", "fdisk", "mkfs", "dd if=", "dd of=",
	"cipher /w", "sdelete", "shred", "wipe",
	
	// System shutdown/restart
	"shutdown", "reboot", "halt", "poweroff", "restart",
	"systemctl stop", "systemctl disable", "service stop",
	
	// Process termination (except read-only)
	"kill -9", "kill -KILL", "taskkill /f", "pkill -9",
	
	// User/group modification
	"useradd", "userdel", "usermod", "groupadd", "groupdel",
	"passwd", "chpasswd", "net user", "net localgroup",
	
	// Permission changes
	"chmod 777", "chmod +x", "chown", "chgrp", "icacls",
	"takeown", "cacls", "attrib +h", "attrib +s",
	
	// Network configuration changes
	"iptables", "ufw", "firewall", "netsh", "route add",
	"ifconfig", "ip route", "ip addr",
	
	// Registry modifications
	"reg add", "reg delete", "regedit /s", "regsvr32",
	
	// Service modifications
	"sc create", "sc delete", "sc config", "systemctl start",
	"systemctl enable", "chkconfig",
	
	// Malware-like behavior
	"base64 -d", "certutil -decode", "powershell -enc",
	"cmd /c echo", "cmd.exe /c", "powershell -ep bypass",
	"powershell -w hidden", "wscript", "cscript",
	
	// Dangerous system utilities
	"schtasks /create", "at ", "crontab -e", "crontab -r",
	"mount", "umount", "fsck", "chkdsk /f",
}

// File paths that should never be accessed/modified
var BlockedPaths = []string{
	// System files
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
	"/boot/", "/dev/", "/proc/", "/sys/",
	"C:\\Windows\\System32", "C:\\Windows\\SysWOW64",
	"C:\\Windows\\Boot", "C:\\Windows\\security",
	
	// User data
	"/home/", "/Users/", "C:\\Users\\",
	"/root/", "C:\\Documents and Settings\\",
	
	// Application data
	"/var/lib/", "/opt/", "C:\\Program Files\\",
	"C:\\Program Files (x86)\\", "/Applications/",
	
	// Network configurations
	"/etc/network/", "/etc/NetworkManager/",
	"C:\\Windows\\System32\\drivers\\etc\\",
}

// DefaultSafetyRules defines the safety constraints for bug bounty testing
var DefaultSafetyRules = []SafetyRule{
	{
		Name:        "No Destructive Actions",
		Description: "Prevent any commands that could damage or modify system",
		Check: func(cmd string) bool {
			return !containsDestructiveCommand(cmd)
		},
	},
	{
		Name:        "Read-Only Operations",
		Description: "Only allow read-only operations and checks",
		Check: func(cmd string) bool {
			return isReadOnlyOperation(cmd)
		},
	},
	{
		Name:        "No System File Access",
		Description: "Prevent access to critical system files and directories",
		Check: func(cmd string) bool {
			return !accessesBlockedPaths(cmd)
		},
	},
	{
		Name:        "Time Limited",
		Description: "Enforce maximum execution time",
		Enforce: func(ctx context.Context) context.Context {
			ctx, _ = context.WithTimeout(ctx, 30*time.Second)
			return ctx
		},
	},
	{
		Name:        "No Elevation Required",
		Description: "Prevent tests requiring administrative privileges",
		Check: func(cmd string) bool {
			return !requiresElevation(cmd)
		},
	},
	{
		Name:        "No Network Modifications",
		Description: "Prevent network configuration changes",
		Check: func(cmd string) bool {
			return !modifiesNetwork(cmd)
		},
	},
}

// IsSafe checks if an atomic test is safe for bug bounty execution
func (s *SafetyFilter) IsSafe(test AtomicTest) bool {
	// 1. Check if technique is in whitelist
	if !s.isTechniqueAllowed(test.AttackTechnique) {
		return false
	}
	
	// 2. Check each atomic test within the technique
	for _, atomicTest := range test.AtomicTests {
		if !s.isAtomicTestSafe(atomicTest) {
			return false
		}
	}
	
	return true
}

// isTechniqueAllowed checks if ATT&CK technique is whitelisted
func (s *SafetyFilter) isTechniqueAllowed(technique string) bool {
	for _, allowed := range s.allowedTechniques {
		if allowed == technique {
			return true
		}
	}
	return false
}

// isAtomicTestSafe checks if individual atomic test is safe
func (s *SafetyFilter) isAtomicTestSafe(test Test) bool {
	// 1. No elevation required
	if test.Executor.ElevationRequired {
		return false
	}
	
	// 2. No cleanup commands (modifications)
	if test.Executor.CleanupCommand != "" {
		return false
	}
	
	// 3. Check command against safety rules
	for _, rule := range s.safetyRules {
		if rule.Check != nil && !rule.Check(test.Executor.Command) {
			return false
		}
	}
	
	// 4. Check for blocked commands
	if s.containsBlockedCommand(test.Executor.Command) {
		return false
	}
	
	// 5. Check dependencies are safe
	for _, dep := range test.Dependencies {
		if dep.GetPrereqCommand != "" && s.containsBlockedCommand(dep.GetPrereqCommand) {
			return false
		}
	}
	
	return true
}

// containsBlockedCommand checks if command contains dangerous operations
func (s *SafetyFilter) containsBlockedCommand(command string) bool {
	cmdLower := strings.ToLower(command)
	
	for _, blocked := range s.blockedCommands {
		if strings.Contains(cmdLower, strings.ToLower(blocked)) {
			return true
		}
	}
	
	return false
}

// containsDestructiveCommand checks for destructive operations
func containsDestructiveCommand(command string) bool {
	destructivePatterns := []string{
		`rm\s+-[rf]`, `del\s+/[fqs]`, `format\s+`, `fdisk`,
		`shutdown`, `reboot`, `halt`, `kill\s+-9`,
		`chmod\s+777`, `chown`, `useradd`, `userdel`,
		`reg\s+add`, `reg\s+delete`, `sc\s+create`,
		`schtasks\s+/create`, `net\s+user.*\/add`,
	}
	
	cmdLower := strings.ToLower(command)
	for _, pattern := range destructivePatterns {
		if matched, _ := regexp.MatchString(pattern, cmdLower); matched {
			return true
		}
	}
	
	return false
}

// isReadOnlyOperation checks if operation is read-only
func isReadOnlyOperation(command string) bool {
	readOnlyCommands := []string{
		"ls", "dir", "cat", "type", "head", "tail", "more", "less",
		"find", "grep", "awk", "sed", "sort", "uniq", "wc",
		"ps", "top", "netstat", "ss", "lsof", "who", "w",
		"uname", "hostname", "whoami", "id", "groups",
		"mount | grep", "df", "du", "free", "uptime",
		"systemctl status", "service status",
		"reg query", "wmic", "get-", "test-",
	}
	
	cmdLower := strings.ToLower(command)
	for _, readOnly := range readOnlyCommands {
		if strings.HasPrefix(cmdLower, readOnly) {
			return true
		}
	}
	
	return false
}

// accessesBlockedPaths checks if command accesses restricted paths
func accessesBlockedPaths(command string) bool {
	for _, blockedPath := range BlockedPaths {
		if strings.Contains(command, blockedPath) {
			return true
		}
	}
	return false
}

// requiresElevation checks if command requires administrative privileges
func requiresElevation(command string) bool {
	elevationPatterns := []string{
		"sudo", "su -", "runas", "elevation",
		"administrator", "admin", "root",
		"net localgroup administrators",
		"add-localgroupmember",
	}
	
	cmdLower := strings.ToLower(command)
	for _, pattern := range elevationPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}
	
	return false
}

// modifiesNetwork checks if command modifies network configuration
func modifiesNetwork(command string) bool {
	networkModPatterns := []string{
		"iptables", "ufw", "firewall", "netsh",
		"route add", "route delete", "ip route",
		"ifconfig.*up", "ifconfig.*down",
		"systemctl.*network", "service.*network",
	}
	
	cmdLower := strings.ToLower(command)
	for _, pattern := range networkModPatterns {
		if matched, _ := regexp.MatchString(pattern, cmdLower); matched {
			return true
		}
	}
	
	return false
}

// ValidateTest performs comprehensive safety validation
func (s *SafetyFilter) ValidateTest(test AtomicTest, target Target) error {
	if !s.IsSafe(test) {
		return fmt.Errorf("test %s (%s) failed safety validation", test.DisplayName, test.AttackTechnique)
	}
	
	// Additional target-specific validation
	if target.URL != "" {
		if !s.isTargetInScope(target.URL) {
			return fmt.Errorf("target %s is not in authorized scope", target.URL)
		}
	}
	
	return nil
}

// isTargetInScope checks if target is within authorized scope
func (s *SafetyFilter) isTargetInScope(targetURL string) bool {
	// In real implementation, this would check against authorized domains/IPs
	// For bug bounty, ensure target is within program scope
	
	// Prevent localhost testing unless explicitly allowed
	if strings.Contains(targetURL, "localhost") || strings.Contains(targetURL, "127.0.0.1") {
		return false
	}
	
	// Prevent internal network ranges
	internalPatterns := []string{
		"192.168.", "10.", "172.16.", "172.17.", "172.18.",
		"172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
		"172.29.", "172.30.", "172.31.",
	}
	
	for _, pattern := range internalPatterns {
		if strings.Contains(targetURL, pattern) {
			return false
		}
	}
	
	return true
}

// GetSafetyReport generates a safety validation report
func (s *SafetyFilter) GetSafetyReport(test AtomicTest) SafetyReport {
	report := SafetyReport{
		Technique:   test.AttackTechnique,
		TestName:    test.DisplayName,
		IsSafe:      s.IsSafe(test),
		Violations:  []string{},
		Warnings:    []string{},
		Checks:      []SafetyCheck{},
	}
	
	// Detailed safety analysis
	for _, atomicTest := range test.AtomicTests {
		for _, rule := range s.safetyRules {
			check := SafetyCheck{
				RuleName: rule.Name,
				Passed:   true,
				Details:  "",
			}
			
			if rule.Check != nil && !rule.Check(atomicTest.Executor.Command) {
				check.Passed = false
				check.Details = fmt.Sprintf("Command failed safety check: %s", atomicTest.Executor.Command)
				report.Violations = append(report.Violations, check.Details)
				report.IsSafe = false
			}
			
			report.Checks = append(report.Checks, check)
		}
	}
	
	return report
}

// SafetyReport represents safety validation results
type SafetyReport struct {
	Technique  string        `json:"technique"`
	TestName   string        `json:"test_name"`
	IsSafe     bool          `json:"is_safe"`
	Violations []string      `json:"violations"`
	Warnings   []string      `json:"warnings"`
	Checks     []SafetyCheck `json:"checks"`
}

// SafetyCheck represents individual safety rule check
type SafetyCheck struct {
	RuleName string `json:"rule_name"`
	Passed   bool   `json:"passed"`
	Details  string `json:"details"`
}