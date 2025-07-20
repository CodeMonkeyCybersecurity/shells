// pkg/ml/predictor_helpers.go
package ml

import (
	"fmt"
	"regexp"
	"strings"
)

// Helper functions for predictor

// contains checks if a value contains a target string
func contains(value interface{}, target interface{}) bool {
	strValue := fmt.Sprintf("%v", value)
	strTarget := fmt.Sprintf("%v", target)
	return strings.Contains(strValue, strTarget)
}

// compareNumeric compares numeric values
func compareNumeric(value interface{}, target interface{}, operator string) bool {
	// Convert to float64 for comparison
	var numValue, numTarget float64

	switch v := value.(type) {
	case float64:
		numValue = v
	case int:
		numValue = float64(v)
	case string:
		fmt.Sscanf(v, "%f", &numValue)
	default:
		return false
	}

	switch t := target.(type) {
	case float64:
		numTarget = t
	case int:
		numTarget = float64(t)
	case string:
		fmt.Sscanf(t, "%f", &numTarget)
	default:
		return false
	}

	switch operator {
	case ">":
		return numValue > numTarget
	case "<":
		return numValue < numTarget
	case ">=":
		return numValue >= numTarget
	case "<=":
		return numValue <= numTarget
	default:
		return false
	}
}

// matchesRegex checks if a value matches a regex pattern
func matchesRegex(value interface{}, pattern interface{}) bool {
	strValue := fmt.Sprintf("%v", value)
	strPattern := fmt.Sprintf("%v", pattern)

	re, err := regexp.Compile(strPattern)
	if err != nil {
		return false
	}

	return re.MatchString(strValue)
}

// isIn checks if a value is in a list
func isIn(value interface{}, list interface{}) bool {
	strValue := fmt.Sprintf("%v", value)

	// Handle different list types
	switch l := list.(type) {
	case []string:
		for _, item := range l {
			if item == strValue {
				return true
			}
		}
	case []interface{}:
		for _, item := range l {
			if fmt.Sprintf("%v", item) == strValue {
				return true
			}
		}
	case string:
		// Assume comma-separated list
		items := strings.Split(l, ",")
		for _, item := range items {
			if strings.TrimSpace(item) == strValue {
				return true
			}
		}
	}

	return false
}
