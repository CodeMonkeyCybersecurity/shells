package security

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ValidateTarget validates and sanitizes target inputs
func ValidateTarget(target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target cannot be empty")
	}

	// Remove any dangerous characters
	target = strings.TrimSpace(target)
	if strings.ContainsAny(target, ";|&`$(){}[]<>") {
		return "", fmt.Errorf("target contains invalid characters")
	}

	// Check if it's a valid URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		parsedURL, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("invalid URL format: %w", err)
		}
		if parsedURL.Host == "" {
			return "", fmt.Errorf("URL must have a valid host")
		}
		return target, nil
	}

	// Check if it's a valid IP address
	if net.ParseIP(target) != nil {
		return target, nil
	}

	// Check if it's a valid CIDR range
	if _, _, err := net.ParseCIDR(target); err == nil {
		return target, nil
	}

	// Check if it's a valid hostname/domain
	if IsValidHostname(target) {
		return target, nil
	}

	return "", fmt.Errorf("invalid target format: must be URL, IP, CIDR, or hostname")
}

// ValidatePortRange validates port range input
func ValidatePortRange(ports string) (string, error) {
	if ports == "" {
		return "1-65535", nil
	}

	// Remove any dangerous characters
	ports = strings.TrimSpace(ports)
	if strings.ContainsAny(ports, ";|&`$(){}[]<>") {
		return "", fmt.Errorf("port range contains invalid characters")
	}

	// Validate port range format
	portRegex := regexp.MustCompile(`^(\d+(-\d+)?)(,\d+(-\d+)?)*$`)
	if !portRegex.MatchString(ports) {
		return "", fmt.Errorf("invalid port range format")
	}

	// Validate individual ports
	parts := strings.Split(ports, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return "", fmt.Errorf("invalid port range: %s", part)
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil || start < 1 || start > 65535 {
				return "", fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil || end < 1 || end > 65535 {
				return "", fmt.Errorf("invalid end port: %s", rangeParts[1])
			}
			if start > end {
				return "", fmt.Errorf("start port cannot be greater than end port")
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return "", fmt.Errorf("invalid port: %s", part)
			}
		}
	}

	return ports, nil
}

// ValidatePort validates a single port
func ValidatePort(port string) (int, error) {
	if port == "" {
		return 0, fmt.Errorf("port cannot be empty")
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("port must be a number")
	}

	if portNum < 1 || portNum > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}

	return portNum, nil
}

// ValidateFilename validates and sanitizes filename input
func ValidateFilename(filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("filename cannot be empty")
	}

	// Remove path traversal attempts
	filename = filepath.Base(filename)
	
	// Check for dangerous characters
	if strings.ContainsAny(filename, ";|&`$(){}[]<>") {
		return "", fmt.Errorf("filename contains invalid characters")
	}

	// Ensure it's not a special file
	if filename == "." || filename == ".." || strings.HasPrefix(filename, ".") {
		return "", fmt.Errorf("invalid filename")
	}

	return filename, nil
}

// IsValidHostname checks if a string is a valid hostname
func IsValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Check for valid hostname format
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return hostnameRegex.MatchString(hostname)
}

// SanitizeCommand sanitizes command arguments to prevent injection
func SanitizeCommand(args []string) []string {
	sanitized := make([]string, 0, len(args))
	for _, arg := range args {
		// Remove dangerous characters
		arg = strings.TrimSpace(arg)
		if !strings.ContainsAny(arg, ";|&`$(){}[]<>") {
			sanitized = append(sanitized, arg)
		}
	}
	return sanitized
}

// ValidateTimeout validates timeout duration string
func ValidateTimeout(timeout string) (string, error) {
	if timeout == "" {
		return "30s", nil
	}

	// Basic validation - must match duration format
	durationRegex := regexp.MustCompile(`^\d+[smh]$`)
	if !durationRegex.MatchString(timeout) {
		return "", fmt.Errorf("invalid timeout format, use format like '30s', '5m', '1h'")
	}

	return timeout, nil
}