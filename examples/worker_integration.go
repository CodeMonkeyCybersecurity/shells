package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/workers"
)

func main() {
	// Create worker client
	client := workers.NewClient("http://localhost:8000")

	ctx := context.Background()

	// Example 1: Scan GraphQL endpoint
	fmt.Println("🔍 Starting GraphQL scan...")
	graphQLResult, err := scanGraphQLExample(ctx, client)
	if err != nil {
		log.Printf("GraphQL scan failed: %v", err)
	} else {
		fmt.Printf("✅ GraphQL scan completed: %+v\n", graphQLResult)
	}

	fmt.Println()

	// Example 2: Scan for IDOR
	fmt.Println("🔍 Starting IDOR scan...")
	idorResult, err := scanIDORExample(ctx, client)
	if err != nil {
		log.Printf("IDOR scan failed: %v", err)
	} else {
		fmt.Printf("✅ IDOR scan completed: %+v\n", idorResult)
	}
}

func scanGraphQLExample(ctx context.Context, client *workers.Client) (*workers.JobStatus, error) {
	endpoint := "https://api.example.com/graphql"
	authHeader := "Bearer YOUR_TOKEN_HERE"

	// Synchronous scan (waits for completion)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := client.ScanGraphQLSync(ctx, endpoint, &authHeader)
	if err != nil {
		return nil, fmt.Errorf("GraphQL scan error: %w", err)
	}

	if result.Status == "failed" {
		return nil, fmt.Errorf("scan failed: %s", *result.Error)
	}

	// Process results
	if result.Result != nil {
		fmt.Println("GraphQL Scan Results:")
		if queries, ok := result.Result["queries"].([]interface{}); ok {
			fmt.Printf("  Found %d queries\n", len(queries))
		}
		if mutations, ok := result.Result["mutations_enabled"].(bool); ok && mutations {
			fmt.Println("  ⚠️  Mutations are enabled!")
		}
	}

	return result, nil
}

func scanIDORExample(ctx context.Context, client *workers.Client) (*workers.JobStatus, error) {
	endpoint := "https://api.example.com/users/{id}"

	// Create test tokens (in practice, you'd create these from test accounts)
	tokens := []string{
		"TOKEN_USER_1",
		"TOKEN_USER_2",
	}

	// Scan for IDOR vulnerabilities in ID range 1-50
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := client.ScanIDORSync(ctx, endpoint, tokens, 1, 50)
	if err != nil {
		return nil, fmt.Errorf("IDOR scan error: %w", err)
	}

	if result.Status == "failed" {
		return nil, fmt.Errorf("scan failed: %s", *result.Error)
	}

	// Process results
	if result.Result != nil {
		if count, ok := result.Result["findings_count"].(float64); ok {
			fmt.Printf("  Found %d IDOR vulnerabilities\n", int(count))

			if findings, ok := result.Result["findings"].([]interface{}); ok {
				for _, finding := range findings {
					if f, ok := finding.(map[string]interface{}); ok {
						fmt.Printf("  🎯 IDOR: %s (Severity: %s)\n", f["url"], f["severity"])
					}
				}
			}
		}
	}

	return result, nil
}

// Example: Async scanning
func asyncScanExample(ctx context.Context, client *workers.Client) {
	// Start scan without waiting
	status, err := client.ScanGraphQL(ctx, "https://api.example.com/graphql", nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Started job: %s\n", status.JobID)

	// Do other work...

	// Check status later
	time.Sleep(10 * time.Second)

	finalStatus, err := client.GetJobStatus(ctx, status.JobID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Job status: %s\n", finalStatus.Status)
}
