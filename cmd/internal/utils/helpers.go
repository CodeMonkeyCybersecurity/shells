package utils

// Pure utility functions with no side effects or external dependencies.
// These are simple helper functions used across the cmd package.

// UniqueStrings returns a deduplicated slice of strings, preserving order.
// Empty strings are filtered out.
func UniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, str := range strs {
		if !seen[str] && str != "" {
			seen[str] = true
			result = append(result, str)
		}
	}
	return result
}

// Min returns the smaller of two integers.
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
