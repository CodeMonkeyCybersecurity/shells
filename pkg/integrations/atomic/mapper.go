package atomic

import (
	"fmt"
	"strings"
)

// VulnToAttackMapper maps vulnerability types to MITRE ATT&CK techniques
type VulnToAttackMapper struct {
	mappings      map[string][]string
	descriptions  map[string]string
	tactics       map[string]string
}

// NewVulnToAttackMapper creates a new vulnerability to ATT&CK mapper
func NewVulnToAttackMapper() *VulnToAttackMapper {
	return &VulnToAttackMapper{
		mappings:     VulnerabilityToATTACK,
		descriptions: TechniqueDescriptions,
		tactics:      TechniqueTactics,
	}
}

// Comprehensive mapping of vulnerability types to ATT&CK techniques
var VulnerabilityToATTACK = map[string][]string{
	// Web Application Vulnerabilities
	"SSRF": {"T1219", "T1090", "T1083"}, // Remote Access Software, Proxy, File Discovery
	"XXE": {"T1005", "T1083", "T1552.001"}, // Data from Local System, File Discovery, Credentials in Files
	"SQLI": {"T1190", "T1005", "T1552"}, // Exploit Public-Facing App, Data from Local System, Credentials
	"RCE": {"T1059", "T1106", "T1003"}, // Command Interpreter, Native API, Credential Dumping
	"LFI": {"T1005", "T1083", "T1552.001"}, // Data from Local System, File Discovery, Credentials in Files
	"RFI": {"T1105", "T1059", "T1190"}, // Ingress Tool Transfer, Command Interpreter, Exploit Public App
	"COMMAND_INJECTION": {"T1059", "T1190", "T1068"}, // Command Interpreter, Exploit Public App, Privilege Escalation
	"PATH_TRAVERSAL": {"T1083", "T1005", "T1552.001"}, // File Discovery, Data from Local System, Credentials in Files
	"UPLOAD_VULNERABILITY": {"T1105", "T1059", "T1036"}, // Ingress Tool Transfer, Command Interpreter, Masquerading
	"DESERIALIZATION": {"T1059", "T1190", "T1068"}, // Command Interpreter, Exploit Public App, Privilege Escalation
	"TEMPLATE_INJECTION": {"T1059", "T1005", "T1083"}, // Command Interpreter, Data from Local System, File Discovery
	"XPATH_INJECTION": {"T1005", "T1552", "T1190"}, // Data from Local System, Credentials, Exploit Public App
	"LDAP_INJECTION": {"T1087", "T1069", "T1552"}, // Account Discovery, Permission Groups Discovery, Credentials
	"XML_INJECTION": {"T1005", "T1083", "T1027"}, // Data from Local System, File Discovery, Obfuscated Files
	
	// Authentication & Session Vulnerabilities
	"WEAK_AUTHENTICATION": {"T1078", "T1110", "T1552"}, // Valid Accounts, Brute Force, Credentials
	"SESSION_FIXATION": {"T1078", "T1134", "T1556"}, // Valid Accounts, Access Token Manipulation, Modify Authentication
	"SESSION_HIJACKING": {"T1078", "T1185", "T1539"}, // Valid Accounts, Browser Session Hijacking, Steal Web Session Cookie
	"BROKEN_AUTHENTICATION": {"T1078", "T1110", "T1555"}, // Valid Accounts, Brute Force, Credentials from Password Stores
	"JWT_VULNERABILITY": {"T1552", "T1078", "T1134"}, // Credentials, Valid Accounts, Access Token Manipulation
	"OAUTH_VULNERABILITY": {"T1078", "T1552", "T1134"}, // Valid Accounts, Credentials, Access Token Manipulation
	"SAML_VULNERABILITY": {"T1078", "T1552", "T1134"}, // Valid Accounts, Credentials, Access Token Manipulation
	"PASSWORD_POLICY_BYPASS": {"T1110", "T1078", "T1555"}, // Brute Force, Valid Accounts, Credentials from Password Stores
	"MFA_BYPASS": {"T1078", "T1556", "T1621"}, // Valid Accounts, Modify Authentication Process, Multi-Factor Authentication Request Generation
	"CSRF": {"T1185", "T1078", "T1102"}, // Browser Session Hijacking, Valid Accounts, Web Service
	
	// Cloud Infrastructure Vulnerabilities
	"PUBLIC_S3_BUCKET": {"T1530", "T1552.005", "T1087.004"}, // Data from Cloud Storage, Cloud Instance Metadata API, Cloud Account Discovery
	"EXPOSED_CLOUD_STORAGE": {"T1530", "T1552.005", "T1619"}, // Data from Cloud Storage, Cloud Instance Metadata API, Cloud Storage Object Discovery
	"EXPOSED_CLOUD_INSTANCE": {"T1552.005", "T1078.004", "T1087.004"}, // Cloud Instance Metadata API, Cloud Accounts, Cloud Account Discovery
	"CLOUD_MISCONFIG": {"T1530", "T1078.004", "T1098"}, // Data from Cloud Storage, Cloud Accounts, Account Manipulation
	"OVERPRIVILEGED_ROLE": {"T1098", "T1078.004", "T1069.003"}, // Account Manipulation, Cloud Accounts, Cloud Groups
	"NO_MFA_CLOUD": {"T1078.004", "T1556", "T1621"}, // Cloud Accounts, Modify Authentication Process, Multi-Factor Authentication Request Generation
	"EXPOSED_CLOUD_KEYS": {"T1552.005", "T1552.001", "T1078.004"}, // Cloud Instance Metadata API, Credentials in Files, Cloud Accounts
	"CLOUD_PRIVILEGE_ESCALATION": {"T1068", "T1078.004", "T1098"}, // Exploitation for Privilege Escalation, Cloud Accounts, Account Manipulation
	"EXPOSED_METADATA_API": {"T1552.005", "T1087.004", "T1069.003"}, // Cloud Instance Metadata API, Cloud Account Discovery, Cloud Groups
	"IAM_MISCONFIG": {"T1098", "T1078.004", "T1069.003"}, // Account Manipulation, Cloud Accounts, Cloud Groups
	
	// Infrastructure & Network Vulnerabilities
	"DEFAULT_CREDENTIALS": {"T1078", "T1110.001", "T1552.001"}, // Valid Accounts, Password Guessing, Credentials in Files
	"EXPOSED_SERVICE": {"T1046", "T1190", "T1018"}, // Network Service Scanning, Exploit Public-Facing Application, Remote System Discovery
	"OPEN_DATABASE": {"T1530", "T1005", "T1552"}, // Data from Cloud Storage, Data from Local System, Credentials
	"EXPOSED_MONGODB": {"T1530", "T1005", "T1552"}, // Data from Cloud Storage, Data from Local System, Credentials
	"EXPOSED_ELASTICSEARCH": {"T1530", "T1005", "T1552"}, // Data from Cloud Storage, Data from Local System, Credentials
	"EXPOSED_REDIS": {"T1530", "T1005", "T1552"}, // Data from Cloud Storage, Data from Local System, Credentials
	"INSECURE_PROTOCOL": {"T1040", "T1041", "T1071"}, // Network Sniffing, Exfiltration Over C2 Channel, Application Layer Protocol
	"UNENCRYPTED_TRAFFIC": {"T1040", "T1557", "T1552"}, // Network Sniffing, Adversary-in-the-Middle, Credentials
	"WEAK_SSL_TLS": {"T1040", "T1557", "T1552"}, // Network Sniffing, Adversary-in-the-Middle, Credentials
	"EXPOSED_API": {"T1190", "T1087", "T1083"}, // Exploit Public-Facing Application, Account Discovery, File and Directory Discovery
	"API_KEY_EXPOSURE": {"T1552.001", "T1552.002", "T1078"}, // Credentials in Files, Credentials in Registry, Valid Accounts
	
	// Container & Orchestration Vulnerabilities
	"DOCKER_MISCONFIG": {"T1610", "T1611", "T1068"}, // Deploy Container, Escape to Host, Exploitation for Privilege Escalation
	"K8S_MISCONFIG": {"T1610", "T1078.004", "T1087.004"}, // Deploy Container, Cloud Accounts, Cloud Account Discovery
	"EXPOSED_DOCKER_API": {"T1046", "T1610", "T1611"}, // Network Service Scanning, Deploy Container, Escape to Host
	"CONTAINER_ESCAPE": {"T1611", "T1068", "T1055"}, // Escape to Host, Exploitation for Privilege Escalation, Process Injection
	"PRIVILEGED_CONTAINER": {"T1610", "T1611", "T1068"}, // Deploy Container, Escape to Host, Exploitation for Privilege Escalation
	"INSECURE_REGISTRY": {"T1105", "T1610", "T1036"}, // Ingress Tool Transfer, Deploy Container, Masquerading
	
	// Data Exposure & Privacy Vulnerabilities
	"PII_EXPOSURE": {"T1005", "T1039", "T1114"}, // Data from Local System, Data from Network Shared Drive, Email Collection
	"SENSITIVE_DATA_EXPOSURE": {"T1005", "T1552", "T1039"}, // Data from Local System, Credentials, Data from Network Shared Drive
	"BACKUP_EXPOSURE": {"T1005", "T1552.001", "T1083"}, // Data from Local System, Credentials in Files, File and Directory Discovery
	"LOG_EXPOSURE": {"T1005", "T1552.001", "T1083"}, // Data from Local System, Credentials in Files, File and Directory Discovery
	"DATABASE_DUMP": {"T1005", "T1552", "T1530"}, // Data from Local System, Credentials, Data from Cloud Storage
	"SOURCE_CODE_EXPOSURE": {"T1083", "T1552.001", "T1005"}, // File and Directory Discovery, Credentials in Files, Data from Local System
	
	// Business Logic & Authorization Vulnerabilities
	"IDOR": {"T1087", "T1005", "T1083"}, // Account Discovery, Data from Local System, File and Directory Discovery
	"PRIVILEGE_ESCALATION": {"T1068", "T1078", "T1134"}, // Exploitation for Privilege Escalation, Valid Accounts, Access Token Manipulation
	"ACCESS_CONTROL_BYPASS": {"T1078", "T1134", "T1068"}, // Valid Accounts, Access Token Manipulation, Exploitation for Privilege Escalation
	"AUTHORIZATION_BYPASS": {"T1078", "T1134", "T1098"}, // Valid Accounts, Access Token Manipulation, Account Manipulation
	"RATE_LIMITING_BYPASS": {"T1110", "T1078", "T1102"}, // Brute Force, Valid Accounts, Web Service
	"WORKFLOW_BYPASS": {"T1078", "T1134", "T1102"}, // Valid Accounts, Access Token Manipulation, Web Service
	
	// Client-Side Vulnerabilities
	"XSS": {"T1185", "T1539", "T1555"}, // Browser Session Hijacking, Steal Web Session Cookie, Credentials from Password Stores
	"CLICKJACKING": {"T1185", "T1102", "T1566"}, // Browser Session Hijacking, Web Service, Phishing
	"OPEN_REDIRECT": {"T1566", "T1102", "T1219"}, // Phishing, Web Service, Remote Access Software
	"CLIENT_SIDE_TEMPLATE_INJECTION": {"T1059", "T1185", "T1102"}, // Command and Scripting Interpreter, Browser Session Hijacking, Web Service
	"DOM_XSS": {"T1185", "T1539", "T1102"}, // Browser Session Hijacking, Steal Web Session Cookie, Web Service
	"STORED_XSS": {"T1185", "T1539", "T1102"}, // Browser Session Hijacking, Steal Web Session Cookie, Web Service
	"REFLECTED_XSS": {"T1185", "T1566", "T1102"}, // Browser Session Hijacking, Phishing, Web Service
	
	// Cryptographic Vulnerabilities
	"WEAK_CRYPTO": {"T1552", "T1040", "T1059"}, // Credentials, Network Sniffing, Command and Scripting Interpreter
	"HARDCODED_SECRETS": {"T1552.001", "T1078", "T1083"}, // Credentials in Files, Valid Accounts, File and Directory Discovery
	"INSECURE_RANDOM": {"T1552", "T1078", "T1110"}, // Credentials, Valid Accounts, Brute Force
	"CERTIFICATE_VULNERABILITY": {"T1552.004", "T1040", "T1557"}, // Private Keys, Network Sniffing, Adversary-in-the-Middle
	"ENCRYPTION_BYPASS": {"T1552", "T1005", "T1040"}, // Credentials, Data from Local System, Network Sniffing
	
	// Supply Chain & Third-Party Vulnerabilities
	"VULNERABLE_DEPENDENCY": {"T1195", "T1105", "T1059"}, // Supply Chain Compromise, Ingress Tool Transfer, Command and Scripting Interpreter
	"MALICIOUS_PACKAGE": {"T1195.002", "T1105", "T1059"}, // Compromise Software Supply Chain, Ingress Tool Transfer, Command and Scripting Interpreter
	"TYPOSQUATTING": {"T1195.002", "T1566", "T1102"}, // Compromise Software Supply Chain, Phishing, Web Service
	"CDN_COMPROMISE": {"T1195.002", "T1102", "T1071"}, // Compromise Software Supply Chain, Web Service, Application Layer Protocol
	"THIRD_PARTY_INTEGRATION": {"T1078", "T1102", "T1552"}, // Valid Accounts, Web Service, Credentials
}

// TechniqueDescriptions provides human-readable descriptions for techniques
var TechniqueDescriptions = map[string]string{
	"T1003": "OS Credential Dumping - Adversaries may attempt to dump credentials to obtain account login and credential material",
	"T1005": "Data from Local System - Adversaries may search local file systems and remote file shares for files containing passwords",
	"T1012": "Query Registry - Adversaries may interact with the Windows Registry to gather information about the system",
	"T1018": "Remote System Discovery - Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier",
	"T1027": "Obfuscated Files or Information - Adversaries may attempt to make an executable or file difficult to discover or analyze",
	"T1036": "Masquerading - Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate",
	"T1039": "Data from Network Shared Drive - Adversaries may search network shares on computers they have compromised to find files of interest",
	"T1040": "Network Sniffing - Adversaries may sniff network traffic to capture information about an environment",
	"T1041": "Exfiltration Over C2 Channel - Adversaries may steal data by exfiltrating it over an existing command and control channel",
	"T1046": "Network Service Scanning - Adversaries may attempt to get a listing of services running on remote hosts",
	"T1055": "Process Injection - Adversaries may inject code into processes in order to evade process-based defenses",
	"T1057": "Process Discovery - Adversaries may attempt to get information about running processes on a system",
	"T1059": "Command and Scripting Interpreter - Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries",
	"T1068": "Exploitation for Privilege Escalation - Adversaries may exploit software vulnerabilities in an attempt to elevate privileges",
	"T1069": "Permission Groups Discovery - Adversaries may attempt to find group and permission settings",
	"T1070": "Indicator Removal on Host - Adversaries may delete or alter generated artifacts on a system to remove evidence of their presence",
	"T1071": "Application Layer Protocol - Adversaries may communicate using application layer protocols to avoid detection",
	"T1078": "Valid Accounts - Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access",
	"T1082": "System Information Discovery - An adversary may attempt to get detailed information about the operating system and hardware",
	"T1083": "File and Directory Discovery - Adversaries may enumerate files and directories or may search in specific locations",
	"T1087": "Account Discovery - Adversaries may attempt to get a listing of accounts on a system or within an environment",
	"T1090": "Proxy - Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary",
	"T1098": "Account Manipulation - Adversaries may manipulate accounts to maintain access to victim systems",
	"T1102": "Web Service - Adversaries may use an existing, legitimate external Web service as a means for relaying data",
	"T1105": "Ingress Tool Transfer - Adversaries may transfer tools or other files from an external system into a compromised environment",
	"T1106": "Native API - Adversaries may interact with the native OS application programming interface (API) to execute behaviors",
	"T1110": "Brute Force - Adversaries may use brute force techniques to gain access to accounts when passwords are unknown",
	"T1114": "Email Collection - Adversaries may target user email to collect sensitive information",
	"T1134": "Access Token Manipulation - Adversaries may modify access tokens to operate under a different user or system security context",
	"T1185": "Browser Session Hijacking - Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software",
	"T1190": "Exploit Public-Facing Application - Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program",
	"T1195": "Supply Chain Compromise - Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer",
	"T1219": "Remote Access Software - An adversary may use legitimate desktop support and remote access software",
	"T1530": "Data from Cloud Storage Object - Adversaries may access data objects from improperly secured cloud storage",
	"T1539": "Steal Web Session Cookie - An adversary may steal web application or service session cookies",
	"T1552": "Unsecured Credentials - Adversaries may search compromised systems to find and obtain insecurely stored credentials",
	"T1555": "Credentials from Password Stores - Adversaries may search for common password storage locations",
	"T1556": "Modify Authentication Process - Adversaries may modify authentication mechanisms and processes",
	"T1557": "Adversary-in-the-Middle - Adversaries may attempt to position themselves between two or more networked devices",
	"T1564": "Hide Artifacts - Adversaries may attempt to hide artifacts associated with their behaviors",
	"T1566": "Phishing - Adversaries may send phishing messages to gain access to victim systems",
	"T1610": "Deploy Container - Adversaries may deploy a container into an environment to facilitate execution or evade defenses",
	"T1611": "Escape to Host - Adversaries may break out of a container to gain access to the underlying host",
	"T1619": "Cloud Storage Object Discovery - Adversaries may enumerate objects in cloud storage infrastructure",
	"T1621": "Multi-Factor Authentication Request Generation - Adversaries may attempt to bypass multi-factor authentication (MFA)",
}

// TechniqueTactics maps techniques to their primary MITRE ATT&CK tactics
var TechniqueTactics = map[string]string{
	"T1003": "Credential Access",
	"T1005": "Collection", 
	"T1012": "Discovery",
	"T1018": "Discovery",
	"T1027": "Defense Evasion",
	"T1036": "Defense Evasion",
	"T1039": "Collection",
	"T1040": "Discovery",
	"T1041": "Exfiltration",
	"T1046": "Discovery",
	"T1055": "Defense Evasion",
	"T1057": "Discovery",
	"T1059": "Execution",
	"T1068": "Privilege Escalation",
	"T1069": "Discovery",
	"T1070": "Defense Evasion",
	"T1071": "Command and Control",
	"T1078": "Initial Access",
	"T1082": "Discovery",
	"T1083": "Discovery",
	"T1087": "Discovery",
	"T1090": "Command and Control",
	"T1098": "Persistence",
	"T1102": "Command and Control",
	"T1105": "Command and Control",
	"T1106": "Execution",
	"T1110": "Credential Access",
	"T1114": "Collection",
	"T1134": "Defense Evasion",
	"T1185": "Collection",
	"T1190": "Initial Access",
	"T1195": "Initial Access",
	"T1219": "Command and Control",
	"T1530": "Collection",
	"T1539": "Credential Access",
	"T1552": "Credential Access",
	"T1555": "Credential Access",
	"T1556": "Credential Access",
	"T1557": "Credential Access",
	"T1564": "Defense Evasion",
	"T1566": "Initial Access",
	"T1610": "Defense Evasion",
	"T1611": "Privilege Escalation",
	"T1619": "Discovery",
	"T1621": "Credential Access",
}

// GetTechniques returns ATT&CK techniques for a vulnerability type
func (m *VulnToAttackMapper) GetTechniques(vulnType string) []string {
	if techniques, exists := m.mappings[vulnType]; exists {
		return techniques
	}
	return []string{}
}

// GetDescription returns human-readable description for a technique
func (m *VulnToAttackMapper) GetDescription(technique string) string {
	if desc, exists := m.descriptions[technique]; exists {
		return desc
	}
	return fmt.Sprintf("ATT&CK Technique %s", technique)
}

// GetTactic returns the primary tactic for a technique
func (m *VulnToAttackMapper) GetTactic(technique string) string {
	if tactic, exists := m.tactics[technique]; exists {
		return tactic
	}
	return "Unknown"
}

// GetRelevantTests returns atomic tests relevant to a vulnerability
func (m *VulnToAttackMapper) GetRelevantTests(vulnType string, atomicClient *AtomicClient) []AtomicTest {
	techniques := m.GetTechniques(vulnType)
	tests := []AtomicTest{}
	
	for _, technique := range techniques {
		if test, err := atomicClient.GetSafeTest(technique); err == nil {
			tests = append(tests, *test)
		}
	}
	
	return tests
}

// MapFindingToAttack creates comprehensive ATT&CK mapping for a finding
func (m *VulnToAttackMapper) MapFindingToAttack(finding Finding) *AttackMapping {
	techniques := m.GetTechniques(finding.Type)
	
	mapping := &AttackMapping{
		VulnerabilityType: finding.Type,
		VulnerabilityID:   finding.ID,
		Techniques:        []TechniqueMapping{},
		AttackChain:       []AttackStep{},
		Summary:           "",
	}
	
	// Map each technique
	for i, technique := range techniques {
		techMapping := TechniqueMapping{
			ID:          technique,
			Name:        m.GetDescription(technique),
			Tactic:      m.GetTactic(technique),
			Description: m.GetDescription(technique),
			Relevance:   m.calculateRelevance(finding.Type, technique),
		}
		mapping.Techniques = append(mapping.Techniques, techMapping)
		
		// Build attack chain
		step := AttackStep{
			Order:       i + 1,
			Technique:   technique,
			Tactic:      m.GetTactic(technique),
			Description: m.GetDescription(technique),
			Impact:      m.assessTechniqueImpact(technique, finding),
			Evidence:    finding.Description,
		}
		mapping.AttackChain = append(mapping.AttackChain, step)
	}
	
	// Generate summary
	mapping.Summary = m.generateMappingSummary(finding, mapping)
	
	return mapping
}

// calculateRelevance determines how relevant a technique is to a vulnerability
func (m *VulnToAttackMapper) calculateRelevance(vulnType string, technique string) string {
	// Primary mappings are highly relevant
	techniques := m.GetTechniques(vulnType)
	for i, t := range techniques {
		if t == technique {
			if i == 0 {
				return "PRIMARY"
			} else if i < 3 {
				return "HIGH"
			} else {
				return "MEDIUM"
			}
		}
	}
	return "LOW"
}

// assessTechniqueImpact determines the impact of a technique in context
func (m *VulnToAttackMapper) assessTechniqueImpact(technique string, finding Finding) string {
	baseImpact := map[string]string{
		"T1003": "Credential harvesting leading to account compromise",
		"T1552": "Credential exposure enabling unauthorized access",
		"T1530": "Unauthorized data access from cloud storage",
		"T1190": "Initial foothold enabling further compromise",
		"T1078": "Persistent access through legitimate accounts",
		"T1087": "Information gathering for targeted attacks",
		"T1083": "Sensitive file discovery and enumeration",
	}
	
	if impact, exists := baseImpact[technique]; exists {
		return fmt.Sprintf("%s (via %s vulnerability)", impact, finding.Type)
	}
	
	return fmt.Sprintf("Potential security impact through %s", finding.Type)
}

// generateMappingSummary creates executive summary for the mapping
func (m *VulnToAttackMapper) generateMappingSummary(finding Finding, mapping *AttackMapping) string {
	if len(mapping.Techniques) == 0 {
		return fmt.Sprintf("No direct ATT&CK techniques mapped for %s vulnerability", finding.Type)
	}
	
	primaryTactic := mapping.AttackChain[0].Tactic
	techniqueCount := len(mapping.Techniques)
	
	return fmt.Sprintf(
		"The %s vulnerability maps to %d ATT&CK techniques, primarily enabling %s tactics. "+
		"This vulnerability provides an attack path for %s and related adversary behaviors.",
		strings.ReplaceAll(finding.Type, "_", " "), 
		techniqueCount, 
		primaryTactic,
		strings.ToLower(primaryTactic),
	)
}

// AttackMapping represents comprehensive vulnerability to ATT&CK mapping
type AttackMapping struct {
	VulnerabilityType string             `json:"vulnerability_type"`
	VulnerabilityID   string             `json:"vulnerability_id"`
	Techniques        []TechniqueMapping `json:"techniques"`
	AttackChain       []AttackStep       `json:"attack_chain"`
	Summary           string             `json:"summary"`
}

// TechniqueMapping represents individual technique mapping
type TechniqueMapping struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Description string `json:"description"`
	Relevance   string `json:"relevance"`
}