package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

type graphQLScanner struct {
	client *http.Client
	config GraphQLConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

type GraphQLConfig struct {
	Timeout               time.Duration
	MaxDepth              int
	MaxComplexity         int
	BatchSize             int
	UserAgent             string
	EnableIntrospection   bool
	EnableBatching        bool
	EnableComplexity      bool
	EnableDepthAnalysis   bool
	EnableFieldSuggestion bool
	CustomHeaders         map[string]string
}

type GraphQLResponse struct {
	Data   interface{}    `json:"data"`
	Errors []GraphQLError `json:"errors"`
}

type GraphQLError struct {
	Message    string                 `json:"message"`
	Locations  []GraphQLLocation      `json:"locations"`
	Path       []interface{}          `json:"path"`
	Extensions map[string]interface{} `json:"extensions"`
}

type GraphQLLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type IntrospectionResult struct {
	Schema        *Schema           `json:"__schema"`
	Types         []TypeDefinition  `json:"types"`
	Queries       []FieldDefinition `json:"queries"`
	Mutations     []FieldDefinition `json:"mutations"`
	Subscriptions []FieldDefinition `json:"subscriptions"`
}

type Schema struct {
	QueryType        *TypeRef              `json:"queryType"`
	MutationType     *TypeRef              `json:"mutationType"`
	SubscriptionType *TypeRef              `json:"subscriptionType"`
	Types            []TypeDefinition      `json:"types"`
	Directives       []DirectiveDefinition `json:"directives"`
}

type TypeDefinition struct {
	Kind          string            `json:"kind"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Fields        []FieldDefinition `json:"fields"`
	EnumValues    []EnumValue       `json:"enumValues"`
	InputFields   []InputValue      `json:"inputFields"`
	Interfaces    []TypeRef         `json:"interfaces"`
	PossibleTypes []TypeRef         `json:"possibleTypes"`
}

type FieldDefinition struct {
	Name              string       `json:"name"`
	Description       string       `json:"description"`
	Args              []InputValue `json:"args"`
	Type              TypeRef      `json:"type"`
	IsDeprecated      bool         `json:"isDeprecated"`
	DeprecationReason string       `json:"deprecationReason"`
}

type InputValue struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Type         TypeRef `json:"type"`
	DefaultValue string  `json:"defaultValue"`
}

type TypeRef struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OfType *TypeRef `json:"ofType"`
}

type EnumValue struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	IsDeprecated      bool   `json:"isDeprecated"`
	DeprecationReason string `json:"deprecationReason"`
}

type DirectiveDefinition struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Locations   []string     `json:"locations"`
	Args        []InputValue `json:"args"`
}

type GraphQLVulnerability struct {
	Type        string
	Severity    types.Severity
	Query       string
	Response    string
	Description string
	Evidence    string
}

func NewGraphQLScanner(logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	config := GraphQLConfig{
		Timeout:               30 * time.Second,
		MaxDepth:              10,
		MaxComplexity:         1000,
		BatchSize:             10,
		EnableIntrospection:   true,
		EnableBatching:        true,
		EnableComplexity:      true,
		EnableDepthAnalysis:   true,
		EnableFieldSuggestion: true,
		CustomHeaders:         make(map[string]string),
	}

	return &graphQLScanner{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config: config,
		logger: logger,
	}
}

func (s *graphQLScanner) Name() string {
	return "graphql"
}

func (s *graphQLScanner) Type() types.ScanType {
	return types.ScanType("api")
}

func (s *graphQLScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("target must be a valid HTTP/HTTPS URL")
	}

	return nil
}

func (s *graphQLScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	s.logger.Infow("Starting comprehensive GraphQL security scan", "target", target)

	findings := []types.Finding{}

	// 1. Discover GraphQL endpoints
	endpoints := s.discoverGraphQLEndpoints(ctx, target)
	if len(endpoints) == 0 {
		s.logger.Info("No GraphQL endpoints discovered")
		return findings, nil
	}

	s.logger.Infow("Discovered GraphQL endpoints", "count", len(endpoints))

	for _, endpoint := range endpoints {
		s.logger.Debug("Testing GraphQL endpoint", "endpoint", endpoint)

		// 2. Test introspection with full schema dump
		if s.config.EnableIntrospection {
			introspectionFindings := s.testIntrospection(ctx, endpoint, options)
			findings = append(findings, introspectionFindings...)
		}

		// 3. Test batching attacks
		if s.config.EnableBatching {
			batchFindings := s.testBatchingAttacks(ctx, endpoint, options)
			findings = append(findings, batchFindings...)
		}

		// 4. Test query complexity
		if s.config.EnableComplexity {
			complexityFindings := s.testQueryComplexity(ctx, endpoint, options)
			findings = append(findings, complexityFindings...)
		}

		// 5. Test depth limits
		if s.config.EnableDepthAnalysis {
			depthFindings := s.testDepthLimits(ctx, endpoint, options)
			findings = append(findings, depthFindings...)
		}

		// 6. Test field suggestion
		if s.config.EnableFieldSuggestion {
			suggestionFindings := s.testFieldSuggestion(ctx, endpoint, options)
			findings = append(findings, suggestionFindings...)
		}

		// 7. Test authorization bypass
		authFindings := s.testAuthorizationBypass(ctx, endpoint, options)
		findings = append(findings, authFindings...)

		// 8. Test injection vulnerabilities
		injectionFindings := s.testInjectionVulnerabilities(ctx, endpoint, options)
		findings = append(findings, injectionFindings...)

		// 9. Test information disclosure
		disclosureFindings := s.testInformationDisclosure(ctx, endpoint, options)
		findings = append(findings, disclosureFindings...)

		// 10. Test CSRF protection
		csrfFindings := s.testCSRFProtection(ctx, endpoint, options)
		findings = append(findings, csrfFindings...)

		// 11. Test rate limiting
		rateLimitFindings := s.testRateLimiting(ctx, endpoint, options)
		findings = append(findings, rateLimitFindings...)
	}

	s.logger.Infow("GraphQL scan completed", "findings", len(findings))
	return findings, nil
}

func (s *graphQLScanner) discoverGraphQLEndpoints(ctx context.Context, target string) []string {
	endpoints := []string{}

	// Common GraphQL endpoint paths
	commonPaths := []string{
		"/graphql",
		"/graphql/",
		"/graphiql",
		"/api/graphql",
		"/api/graphql/",
		"/v1/graphql",
		"/v2/graphql",
		"/graph",
		"/gql",
		"/query",
		"/api/query",
		"/api/gql",
		"/api/graph",
		"/admin/graphql",
		"/internal/graphql",
		"/dev/graphql",
		"/test/graphql",
		"/staging/graphql",
	}

	baseURL := strings.TrimRight(target, "/")

	for _, path := range commonPaths {
		testURL := baseURL + path

		if s.isGraphQLEndpoint(ctx, testURL) {
			endpoints = append(endpoints, testURL)
		}
	}

	// Test root path
	if s.isGraphQLEndpoint(ctx, baseURL) {
		endpoints = append(endpoints, baseURL)
	}

	return endpoints
}

func (s *graphQLScanner) isGraphQLEndpoint(ctx context.Context, url string) bool {
	// Test with a simple introspection query
	query := `{"query": "{ __schema { queryType { name } } }"}`

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(query))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.UserAgent != "" {
		req.Header.Set("User-Agent", s.config.UserAgent)
	}

	for key, value := range s.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// Check for GraphQL-specific responses
	bodyStr := string(body)
	graphqlIndicators := []string{
		"__schema",
		"queryType",
		"mutationType",
		"subscriptionType",
		"GraphQL",
		"Cannot query field",
		"Syntax Error GraphQL",
		"Field \"__schema\" not found",
	}

	for _, indicator := range graphqlIndicators {
		if strings.Contains(bodyStr, indicator) {
			return true
		}
	}

	// Check Content-Type
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") &&
		(strings.Contains(bodyStr, "data") || strings.Contains(bodyStr, "errors")) {
		return true
	}

	return false
}

func (s *graphQLScanner) testIntrospection(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL introspection with full schema dump", "endpoint", endpoint)

	// Full comprehensive introspection query
	introspectionQuery := `{
		__schema {
			queryType { name }
			mutationType { name }
			subscriptionType { name }
			types {
				...FullType
			}
			directives {
				name
				description
				locations
				args {
					...InputValue
				}
			}
		}
	}

	fragment FullType on __Type {
		kind
		name
		description
		fields(includeDeprecated: true) {
			name
			description
			args {
				...InputValue
			}
			type {
				...TypeRef
			}
			isDeprecated
			deprecationReason
		}
		inputFields {
			...InputValue
		}
		interfaces {
			...TypeRef
		}
		enumValues(includeDeprecated: true) {
			name
			description
			isDeprecated
			deprecationReason
		}
		possibleTypes {
			...TypeRef
		}
	}

	fragment InputValue on __InputValue {
		name
		description
		type { ...TypeRef }
		defaultValue
	}

	fragment TypeRef on __Type {
		kind
		name
		ofType {
			kind
			name
			ofType {
				kind
				name
				ofType {
					kind
					name
					ofType {
						kind
						name
						ofType {
							kind
							name
							ofType {
								kind
								name
								ofType {
									kind
									name
								}
							}
						}
					}
				}
			}
		}
	}`

	payload := map[string]interface{}{
		"query": introspectionQuery,
	}

	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return findings
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.UserAgent != "" {
		req.Header.Set("User-Agent", s.config.UserAgent)
	}

	// Add custom headers from options
	if authHeader := options["auth_header"]; authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	for key, value := range s.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings
	}

	var graphqlResp GraphQLResponse
	if err := json.Unmarshal(body, &graphqlResp); err != nil {
		return findings
	}

	// Check if introspection is enabled
	if graphqlResp.Data != nil {
		schemaData, ok := graphqlResp.Data.(map[string]interface{})
		if ok && schemaData["__schema"] != nil {
			// Introspection is enabled - this is a security finding
			finding := types.Finding{
				Tool:     "graphql",
				Type:     "graphql_introspection_enabled",
				Severity: types.SeverityMedium,
				Title:    "GraphQL Introspection Enabled - Full Schema Exposed",
				Description: "GraphQL introspection is enabled, allowing attackers to discover the complete schema, " +
					"including all available queries, mutations, subscriptions, types, and fields. This provides " +
					"comprehensive reconnaissance information for potential attacks. The complete schema has been " +
					"successfully dumped and is available for analysis.",
				Evidence: fmt.Sprintf("Full introspection query successful at: %s\n\nComplete schema dump available (Response size: %d bytes)\n\nSchema preview:\n%s",
					endpoint, len(body), s.truncateResponse(string(body), 2000)),
				Solution: "Disable GraphQL introspection in production environments:\n" +
					"1. Set introspection: false in your GraphQL server configuration\n" +
					"2. Use schema whitelisting instead of introspection\n" +
					"3. Implement proper authentication before allowing introspection\n" +
					"4. Monitor for introspection queries in logs\n" +
					"5. Consider query whitelisting for production",
				Metadata: map[string]interface{}{
					"endpoint":              endpoint,
					"response_size":         len(body),
					"introspection_enabled": true,
					"full_schema_dump":      string(body),
				},
			}
			findings = append(findings, finding)

			// Parse schema details for additional findings
			s.analyzeIntrospectionResults(endpoint, body, &findings)
		}
	}

	// Check for partial introspection or information leakage in errors
	if len(graphqlResp.Errors) > 0 {
		for _, graphqlError := range graphqlResp.Errors {
			if s.containsSensitiveInfo(graphqlError.Message) {
				finding := types.Finding{
					Tool:        "graphql",
					Type:        "graphql_information_disclosure",
					Severity:    types.SeverityLow,
					Title:       "GraphQL Error Message Information Disclosure",
					Description: "GraphQL error messages contain sensitive information that could aid attackers in understanding the schema structure",
					Evidence:    fmt.Sprintf("Error message: %s\nEndpoint: %s", graphqlError.Message, endpoint),
					Solution: "Configure GraphQL server to return generic error messages in production:\n" +
						"1. Implement custom error formatters\n" +
						"2. Log detailed errors server-side only\n" +
						"3. Use error codes instead of descriptive messages",
					Metadata: map[string]interface{}{
						"endpoint":      endpoint,
						"error_message": graphqlError.Message,
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (s *graphQLScanner) analyzeIntrospectionResults(endpoint string, responseBody []byte, findings *[]types.Finding) {
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return
	}

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		return
	}

	schema, ok := data["__schema"].(map[string]interface{})
	if !ok {
		return
	}

	// Analyze types for sensitive information
	if schemaTypes, ok := schema["types"].([]interface{}); ok {
		sensitiveTypes := s.findSensitiveTypes(schemaTypes)
		if len(sensitiveTypes) > 0 {
			finding := types.Finding{
				Tool:     "graphql",
				Type:     "graphql_sensitive_schema",
				Severity: types.SeverityMedium,
				Title:    "Sensitive Schema Elements Exposed via Introspection",
				Description: "GraphQL schema contains potentially sensitive types, fields, or operations that " +
					"could provide valuable reconnaissance information to attackers",
				Evidence: fmt.Sprintf("Sensitive elements found in schema:\n%s", strings.Join(sensitiveTypes, "\n")),
				Solution: "Review exposed schema elements and remove or secure sensitive operations:\n" +
					"1. Remove debug/test types from production schema\n" +
					"2. Implement field-level authorization\n" +
					"3. Use schema stitching to hide internal types\n" +
					"4. Consider separate schemas for different user roles",
				Metadata: map[string]interface{}{
					"endpoint":           endpoint,
					"sensitive_elements": sensitiveTypes,
					"total_types":        len(schemaTypes),
				},
			}
			*findings = append(*findings, finding)
		}

		// Generate comprehensive schema summary
		s.generateSchemaSummary(endpoint, schema, findings)
	}

	// Check for deprecated fields (potential attack surface)
	deprecatedFields := s.findDeprecatedFields(schema)
	if len(deprecatedFields) > 0 {
		finding := types.Finding{
			Tool:     "graphql",
			Type:     "graphql_deprecated_fields",
			Severity: types.SeverityLow,
			Title:    "Deprecated GraphQL Fields Exposed",
			Description: "Schema contains deprecated fields that may have security vulnerabilities or " +
				"represent legacy code paths that might be less secure",
			Evidence: fmt.Sprintf("Deprecated fields found:\n%s", strings.Join(deprecatedFields, "\n")),
			Solution: "Address deprecated fields:\n" +
				"1. Remove deprecated fields if no longer needed\n" +
				"2. Ensure deprecated fields are properly secured\n" +
				"3. Document migration paths for deprecated functionality\n" +
				"4. Monitor usage of deprecated fields",
			Metadata: map[string]interface{}{
				"endpoint":          endpoint,
				"deprecated_fields": deprecatedFields,
			},
		}
		*findings = append(*findings, finding)
	}
}

func (s *graphQLScanner) generateSchemaSummary(endpoint string, schema map[string]interface{}, findings *[]types.Finding) {
	summary := []string{}

	// Count different schema elements
	if types, ok := schema["types"].([]interface{}); ok {
		summary = append(summary, fmt.Sprintf("Total Types: %d", len(types)))

		// Categorize types
		objectTypes := 0
		scalarTypes := 0
		enumTypes := 0
		interfaceTypes := 0
		unionTypes := 0

		for _, typeInterface := range types {
			if typeObj, ok := typeInterface.(map[string]interface{}); ok {
				if kind, ok := typeObj["kind"].(string); ok {
					switch kind {
					case "OBJECT":
						objectTypes++
					case "SCALAR":
						scalarTypes++
					case "ENUM":
						enumTypes++
					case "INTERFACE":
						interfaceTypes++
					case "UNION":
						unionTypes++
					}
				}
			}
		}

		summary = append(summary,
			fmt.Sprintf("Object Types: %d", objectTypes),
			fmt.Sprintf("Scalar Types: %d", scalarTypes),
			fmt.Sprintf("Enum Types: %d", enumTypes),
			fmt.Sprintf("Interface Types: %d", interfaceTypes),
			fmt.Sprintf("Union Types: %d", unionTypes),
		)
	}

	// Check root types
	if queryType, ok := schema["queryType"].(map[string]interface{}); ok {
		if name, ok := queryType["name"].(string); ok {
			summary = append(summary, fmt.Sprintf("Query Root: %s", name))
		}
	}

	if mutationType, ok := schema["mutationType"].(map[string]interface{}); ok {
		if name, ok := mutationType["name"].(string); ok {
			summary = append(summary, fmt.Sprintf("Mutation Root: %s", name))
		}
	}

	if subscriptionType, ok := schema["subscriptionType"].(map[string]interface{}); ok {
		if name, ok := subscriptionType["name"].(string); ok {
			summary = append(summary, fmt.Sprintf("Subscription Root: %s", name))
		}
	}

	// Count directives
	if directives, ok := schema["directives"].([]interface{}); ok {
		summary = append(summary, fmt.Sprintf("Directives: %d", len(directives)))
	}

	finding := types.Finding{
		Tool:        "graphql",
		Type:        "graphql_schema_summary",
		Severity:    types.SeverityInfo,
		Title:       "GraphQL Schema Analysis Summary",
		Description: "Complete analysis of the exposed GraphQL schema structure and components",
		Evidence:    fmt.Sprintf("Schema Analysis:\n%s", strings.Join(summary, "\n")),
		Solution:    "Review schema exposure and consider implementing access controls",
		Metadata: map[string]interface{}{
			"endpoint":       endpoint,
			"schema_summary": summary,
		},
	}
	*findings = append(*findings, finding)
}

func (s *graphQLScanner) findSensitiveTypes(types []interface{}) []string {
	sensitive := []string{}
	sensitiveKeywords := []string{
		"admin", "internal", "private", "secret", "password", "token", "key",
		"credential", "auth", "session", "user", "email", "phone", "ssn",
		"credit", "payment", "billing", "invoice", "debug", "test", "dev",
		"config", "configuration", "setting", "env", "environment",
	}

	for _, typeInterface := range types {
		typeObj, ok := typeInterface.(map[string]interface{})
		if !ok {
			continue
		}

		name, ok := typeObj["name"].(string)
		if !ok {
			continue
		}

		// Skip built-in GraphQL types
		if strings.HasPrefix(name, "__") {
			continue
		}

		// Check type name
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(strings.ToLower(name), keyword) {
				sensitive = append(sensitive, fmt.Sprintf("Type: %s", name))
				break
			}
		}

		// Check fields for sensitive names
		if fields, ok := typeObj["fields"].([]interface{}); ok {
			for _, fieldInterface := range fields {
				field, ok := fieldInterface.(map[string]interface{})
				if !ok {
					continue
				}

				fieldName, ok := field["name"].(string)
				if !ok {
					continue
				}

				for _, keyword := range sensitiveKeywords {
					if strings.Contains(strings.ToLower(fieldName), keyword) {
						sensitive = append(sensitive, fmt.Sprintf("Field: %s.%s", name, fieldName))
						break
					}
				}
			}
		}
	}

	return sensitive
}

func (s *graphQLScanner) findDeprecatedFields(schema map[string]interface{}) []string {
	deprecated := []string{}

	if types, ok := schema["types"].([]interface{}); ok {
		for _, typeInterface := range types {
			typeObj, ok := typeInterface.(map[string]interface{})
			if !ok {
				continue
			}

			typeName, _ := typeObj["name"].(string)

			if fields, ok := typeObj["fields"].([]interface{}); ok {
				for _, fieldInterface := range fields {
					field, ok := fieldInterface.(map[string]interface{})
					if !ok {
						continue
					}

					if isDeprecated, ok := field["isDeprecated"].(bool); ok && isDeprecated {
						fieldName, _ := field["name"].(string)
						reason, _ := field["deprecationReason"].(string)
						if reason == "" {
							reason = "No reason provided"
						}
						deprecated = append(deprecated, fmt.Sprintf("%s.%s (Reason: %s)", typeName, fieldName, reason))
					}
				}
			}
		}
	}

	return deprecated
}

func (s *graphQLScanner) testBatchingAttacks(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL batching attacks", "endpoint", endpoint)

	// Create a batch of queries to test for batching support and DoS potential
	batchQueries := make([]map[string]interface{}, s.config.BatchSize)
	for i := 0; i < s.config.BatchSize; i++ {
		batchQueries[i] = map[string]interface{}{
			"query": "{ __typename }",
		}
	}

	jsonPayload, _ := json.Marshal(batchQueries)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return findings
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.UserAgent != "" {
		req.Header.Set("User-Agent", s.config.UserAgent)
	}

	if authHeader := options["auth_header"]; authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings
	}

	// Check if batching is supported
	var batchResponse []GraphQLResponse
	if err := json.Unmarshal(body, &batchResponse); err == nil && len(batchResponse) > 1 {
		severity := types.SeverityMedium
		if len(batchResponse) >= s.config.BatchSize {
			severity = types.SeverityHigh
		}

		finding := types.Finding{
			Tool:     "graphql",
			Type:     "graphql_batching_enabled",
			Severity: severity,
			Title:    "GraphQL Query Batching Enabled - DoS Risk",
			Description: "GraphQL server supports query batching, which can be abused for DoS attacks " +
				"by sending multiple expensive queries in a single request. This can bypass rate limiting " +
				"and cause resource exhaustion.",
			Evidence: fmt.Sprintf("Batch of %d queries executed successfully in %v\nEndpoint: %s\nResponse size: %d bytes",
				len(batchResponse), duration, endpoint, len(body)),
			Solution: "Implement batching controls:\n" +
				"1. Limit the number of queries per batch (e.g., 5-10)\n" +
				"2. Implement query complexity analysis for each query in batch\n" +
				"3. Add rate limiting that considers batch size\n" +
				"4. Consider disabling batching in production\n" +
				"5. Monitor for suspicious batching patterns",
			Metadata: map[string]interface{}{
				"endpoint":      endpoint,
				"batch_size":    len(batchResponse),
				"response_time": duration.Milliseconds(),
				"response_size": len(body),
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *graphQLScanner) testQueryComplexity(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL query complexity", "endpoint", endpoint)

	// Test increasingly complex queries
	complexQueries := []struct {
		name  string
		query string
	}{
		{
			"nested_introspection",
			`{ __schema { types { fields { type { ofType { ofType { ofType { name } } } } } } } }`,
		},
		{
			"recursive_schema_query",
			`{ __schema { types { fields { args { type { ofType { ofType { ofType { ofType { name } } } } } } } } } }`,
		},
		{
			"complex_multi_field",
			`{ 
				__schema { 
					queryType { name description fields { name description args { name type { name } } } } 
					mutationType { name description fields { name description args { name type { name } } } }
					subscriptionType { name description fields { name description args { name type { name } } } }
					types { name description kind fields { name description args { name type { name } } } }
					directives { name description locations args { name type { name } } }
				}
			}`,
		},
	}

	for i, testCase := range complexQueries {
		payload := map[string]interface{}{
			"query": testCase.query,
		}

		jsonPayload, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if s.config.UserAgent != "" {
			req.Header.Set("User-Agent", s.config.UserAgent)
		}

		if authHeader := options["auth_header"]; authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}

		start := time.Now()
		resp, err := s.client.Do(req)
		duration := time.Since(start)

		if err != nil {
			continue
		}
		resp.Body.Close()

		// If complex queries execute without limits, it's a finding
		if resp.StatusCode == 200 && duration > 3*time.Second {
			severity := types.SeverityMedium
			if duration > 10*time.Second {
				severity = types.SeverityHigh
			}

			finding := types.Finding{
				Tool:     "graphql",
				Type:     "graphql_no_complexity_limits",
				Severity: severity,
				Title:    "No Query Complexity Limits - DoS Risk",
				Description: "GraphQL server does not implement query complexity limits, allowing expensive queries " +
					"that can cause resource exhaustion and DoS attacks",
				Evidence: fmt.Sprintf("Complex query '%s' (%d) executed in %v without restrictions\nQuery: %s",
					testCase.name, i+1, duration, testCase.query),
				Solution: "Implement query complexity analysis:\n" +
					"1. Calculate query complexity before execution\n" +
					"2. Set maximum complexity limits (e.g., 1000 points)\n" +
					"3. Reject queries exceeding complexity limits\n" +
					"4. Log expensive query attempts\n" +
					"5. Use query depth limiting in combination",
				Metadata: map[string]interface{}{
					"endpoint":       endpoint,
					"query_name":     testCase.name,
					"query_index":    i,
					"execution_time": duration.Milliseconds(),
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *graphQLScanner) testDepthLimits(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL depth limits", "endpoint", endpoint)

	// Generate deeply nested query
	depth := s.config.MaxDepth
	nestedQuery := "{ __schema"
	for i := 0; i < depth; i++ {
		nestedQuery += " { types"
	}
	for i := 0; i < depth; i++ {
		nestedQuery += " }"
	}
	nestedQuery += " }"

	payload := map[string]interface{}{
		"query": nestedQuery,
	}

	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return findings
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.UserAgent != "" {
		req.Header.Set("User-Agent", s.config.UserAgent)
	}

	if authHeader := options["auth_header"]; authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		severity := types.SeverityMedium
		if depth > 15 {
			severity = types.SeverityHigh
		}

		finding := types.Finding{
			Tool:     "graphql",
			Type:     "graphql_no_depth_limits",
			Severity: severity,
			Title:    "No Query Depth Limits - Exponential Resource Consumption",
			Description: "GraphQL server does not implement query depth limits, allowing deeply nested queries " +
				"that can cause exponential resource consumption and DoS attacks",
			Evidence: fmt.Sprintf("Deeply nested query (depth: %d) executed successfully in %v", depth, duration),
			Solution: "Implement query depth analysis:\n" +
				"1. Calculate query depth before execution\n" +
				"2. Set maximum depth limits (typically 7-15 levels)\n" +
				"3. Reject queries exceeding depth limits\n" +
				"4. Monitor for suspicious deep queries\n" +
				"5. Use query complexity analysis in combination",
			Metadata: map[string]interface{}{
				"endpoint":       endpoint,
				"tested_depth":   depth,
				"execution_time": duration.Milliseconds(),
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *graphQLScanner) testFieldSuggestion(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL field suggestion", "endpoint", endpoint)

	// Test invalid field names to see if suggestions are returned
	invalidQueries := []string{
		`{ user }`,          // Missing selection set
		`{ users }`,         // Potentially typo
		`{ admin }`,         // Sensitive field test
		`{ secret }`,        // Sensitive field test
		`{ internal }`,      // Sensitive field test
		`{ debug }`,         // Debug field test
		`{ __schma }`,       // Typo in introspection
		`{ __typ }`,         // Another introspection typo
		`{ configuration }`, // Config field test
		`{ settings }`,      // Settings field test
	}

	var suggestions []string

	for _, query := range invalidQueries {
		payload := map[string]interface{}{
			"query": query,
		}

		jsonPayload, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if s.config.UserAgent != "" {
			req.Header.Set("User-Agent", s.config.UserAgent)
		}

		if authHeader := options["auth_header"]; authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Check for field suggestions in error messages
		bodyStr := string(body)
		if s.containsFieldSuggestions(bodyStr) {
			suggestions = append(suggestions, fmt.Sprintf("Query: %s\nResponse: %s", query, s.truncateResponse(bodyStr, 200)))
		}
	}

	if len(suggestions) > 0 {
		finding := types.Finding{
			Tool:     "graphql",
			Type:     "graphql_field_suggestion",
			Severity: types.SeverityLow,
			Title:    "GraphQL Field Suggestions Enabled - Schema Information Leakage",
			Description: "GraphQL server provides field suggestions in error messages, potentially revealing " +
				"schema information and available fields to attackers",
			Evidence: fmt.Sprintf("Field suggestions found in error responses:\n%s", strings.Join(suggestions, "\n\n")),
			Solution: "Disable field suggestions in production:\n" +
				"1. Configure GraphQL server to return generic error messages\n" +
				"2. Remove 'Did you mean' suggestions from error responses\n" +
				"3. Implement proper error handling that doesn't leak schema info\n" +
				"4. Use custom error formatters",
			Metadata: map[string]interface{}{
				"endpoint":         endpoint,
				"suggestion_count": len(suggestions),
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *graphQLScanner) testAuthorizationBypass(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL authorization bypass", "endpoint", endpoint)

	// Test queries that might bypass authorization
	bypassQueries := []string{
		`{ __schema { queryType { fields { name } } } }`, // Introspection without auth
		`query getUsers { users { id email } }`,          // Direct user access
		`query getAdmins { admins { id username } }`,     // Admin access
		`mutation { deleteUser(id: "1") { success } }`,   // Destructive operation
		`{ me { id email roles permissions } }`,          // Current user info
		`query { user(id: "1") { id email password } }`,  // Password field access
		`query { config { apiKey secret } }`,             // Config access
	}

	for _, query := range bypassQueries {
		// Test without authentication headers
		payload := map[string]interface{}{
			"query": query,
		}

		jsonPayload, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if s.config.UserAgent != "" {
			req.Header.Set("User-Agent", s.config.UserAgent)
		}

		// Intentionally don't set auth headers to test bypass

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		var graphqlResp GraphQLResponse
		if err := json.Unmarshal(body, &graphqlResp); err != nil {
			continue
		}

		// Check if query executed successfully without auth
		if graphqlResp.Data != nil && !s.containsAuthError(graphqlResp.Errors) {
			finding := types.Finding{
				Tool:     "graphql",
				Type:     "graphql_authorization_bypass",
				Severity: types.SeverityHigh,
				Title:    "GraphQL Authorization Bypass - Unauthenticated Access",
				Description: "GraphQL query executed successfully without proper authentication, " +
					"potentially exposing sensitive data or allowing unauthorized operations",
				Evidence: fmt.Sprintf("Query executed without authentication:\n%s\n\nResponse:\n%s",
					query, s.truncateResponse(string(body), 500)),
				Solution: "Implement proper authorization:\n" +
					"1. Require authentication for all non-public queries\n" +
					"2. Implement field-level authorization\n" +
					"3. Validate user permissions before execution\n" +
					"4. Use authorization middleware\n" +
					"5. Implement query whitelisting for unauthenticated access",
				Metadata: map[string]interface{}{
					"endpoint":      endpoint,
					"query":         query,
					"response_size": len(body),
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *graphQLScanner) testInjectionVulnerabilities(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL injection vulnerabilities", "endpoint", endpoint)

	// SQL injection payloads
	sqlPayloads := []string{
		`' OR '1'='1`,
		`' UNION SELECT * FROM users--`,
		`'; DROP TABLE users; --`,
		`' OR 1=1#`,
		`" OR "1"="1`,
		`' AND (SELECT COUNT(*) FROM users) > 0--`,
	}

	// NoSQL injection payloads
	nosqlPayloads := []string{
		`{"$ne": null}`,
		`{"$regex": ".*"}`,
		`{"$where": "this.username == this.password"}`,
		`{"$gt": ""}`,
		`{"$in": []}`,
	}

	var vulnerabilities []string

	// Test SQL injection in query variables
	for _, payload := range sqlPayloads {
		queries := []string{
			fmt.Sprintf(`query { user(id: "%s") { id username } }`, payload),
			fmt.Sprintf(`query { search(term: "%s") { results } }`, payload),
			fmt.Sprintf(`mutation { login(username: "%s", password: "test") { token } }`, payload),
		}

		for _, query := range queries {
			if s.testInjectionQuery(ctx, endpoint, query, "sql_injection", options) {
				vulnerabilities = append(vulnerabilities, fmt.Sprintf("SQL injection with payload: %s", payload))
				break // Only report once per payload type
			}
		}
	}

	// Test NoSQL injection
	for _, payload := range nosqlPayloads {
		queries := []string{
			fmt.Sprintf(`query { user(filter: %s) { id username } }`, payload),
			fmt.Sprintf(`query { search(criteria: %s) { results } }`, payload),
		}

		for _, query := range queries {
			if s.testInjectionQuery(ctx, endpoint, query, "nosql_injection", options) {
				vulnerabilities = append(vulnerabilities, fmt.Sprintf("NoSQL injection with payload: %s", payload))
				break
			}
		}
	}

	if len(vulnerabilities) > 0 {
		finding := types.Finding{
			Tool:     "graphql",
			Type:     "graphql_injection_vulnerability",
			Severity: types.SeverityCritical,
			Title:    "GraphQL Injection Vulnerabilities Detected",
			Description: "GraphQL queries appear vulnerable to injection attacks. Input is not properly " +
				"sanitized before being used in database queries or other operations.",
			Evidence: fmt.Sprintf("Injection vulnerabilities found:\n%s", strings.Join(vulnerabilities, "\n")),
			Solution: "Prevent injection attacks:\n" +
				"1. Use parameterized queries/prepared statements\n" +
				"2. Validate and sanitize all inputs at the GraphQL layer\n" +
				"3. Use an ORM with built-in protections\n" +
				"4. Apply least privilege to database users\n" +
				"5. Implement strict input type validation in GraphQL schema\n" +
				"6. Use query analysis and blocking for suspicious patterns",
			Metadata: map[string]interface{}{
				"endpoint":            endpoint,
				"vulnerabilities":     vulnerabilities,
				"vulnerability_count": len(vulnerabilities),
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *graphQLScanner) testInjectionQuery(ctx context.Context, endpoint, query, injectionType string, options map[string]string) bool {
	payload := map[string]interface{}{
		"query": query,
	}

	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.UserAgent != "" {
		req.Header.Set("User-Agent", s.config.UserAgent)
	}

	if authHeader := options["auth_header"]; authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	bodyStr := string(body)

	// Look for SQL error indicators
	if injectionType == "sql_injection" {
		sqlErrors := []string{
			"syntax error", "mysql", "postgresql", "ora-", "sql server",
			"sqlite", "column", "table", "database", "constraint",
			"duplicate entry", "foreign key", "invalid column",
		}

		for _, errorPattern := range sqlErrors {
			if strings.Contains(strings.ToLower(bodyStr), errorPattern) {
				return true
			}
		}
	}

	// Look for NoSQL error indicators
	if injectionType == "nosql_injection" {
		nosqlErrors := []string{
			"mongodb", "invalid bson", "invalid json", "unexpected token",
			"invalid operator", "unknown operator", "cast error",
		}

		for _, errorPattern := range nosqlErrors {
			if strings.Contains(strings.ToLower(bodyStr), errorPattern) {
				return true
			}
		}
	}

	return false
}

func (s *graphQLScanner) testInformationDisclosure(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL information disclosure", "endpoint", endpoint)

	// Test queries that might reveal sensitive information
	disclosureQueries := []string{
		`{ __schema { types { name } } }`,
		`query { systemInfo { version build environment } }`,
		`query { config { debugMode logLevel apiKeys } }`,
		`query { __type(name: "User") { fields { name type { name } } } }`,
		`query { server { version environment config } }`,
		`query { debug { logs errors stackTrace } }`,
	}

	var disclosures []string

	for _, query := range disclosureQueries {
		payload := map[string]interface{}{
			"query": query,
		}

		jsonPayload, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if s.config.UserAgent != "" {
			req.Header.Set("User-Agent", s.config.UserAgent)
		}

		if authHeader := options["auth_header"]; authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// Check for information disclosure patterns
		disclosurePatterns := []string{
			"version", "build", "environment", "debug", "internal",
			"password", "secret", "token", "key", "config", "api",
			"stacktrace", "exception", "error", "database", "connection",
		}

		for _, pattern := range disclosurePatterns {
			if strings.Contains(strings.ToLower(bodyStr), pattern) {
				disclosures = append(disclosures, fmt.Sprintf("Query: %s\nPattern found: %s\nResponse excerpt: %s",
					query, pattern, s.truncateResponse(bodyStr, 200)))
				break
			}
		}
	}

	if len(disclosures) > 0 {
		finding := types.Finding{
			Tool:     "graphql",
			Type:     "graphql_information_disclosure",
			Severity: types.SeverityMedium,
			Title:    "GraphQL Information Disclosure",
			Description: "GraphQL responses contain potentially sensitive information that could " +
				"aid attackers in understanding the system architecture or finding attack vectors",
			Evidence: fmt.Sprintf("Information disclosure found:\n%s", strings.Join(disclosures, "\n\n")),
			Solution: "Remove sensitive information from GraphQL responses:\n" +
				"1. Filter out debug information in production\n" +
				"2. Implement proper field authorization\n" +
				"3. Review exposed schema elements for sensitive data\n" +
				"4. Use generic error messages\n" +
				"5. Remove version and build information from public APIs",
			Metadata: map[string]interface{}{
				"endpoint":         endpoint,
				"disclosure_count": len(disclosures),
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

func (s *graphQLScanner) testCSRFProtection(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL CSRF protection", "endpoint", endpoint)

	// Test if mutations work without CSRF tokens
	mutations := []string{
		`mutation { __typename }`,
		`mutation TestMutation { __typename }`,
		`mutation { updateUser(id: "1", name: "test") { id } }`,
		`mutation { deleteUser(id: "1") { success } }`,
	}

	for _, mutation := range mutations {
		// Try without any CSRF protection
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(
			fmt.Sprintf(`{"query": "%s"}`, strings.ReplaceAll(mutation, `"`, `\"`)),
		))
		if err != nil {
			continue
		}

		// Minimal headers - no CSRF token, suspicious origin
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://evil.com")
		req.Header.Set("Referer", "http://evil.com/attack.html")

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result GraphQLResponse
			json.NewDecoder(resp.Body).Decode(&result)

			if result.Data != nil {
				finding := types.Finding{
					Tool:     "graphql",
					Type:     "graphql_csrf_vulnerable",
					Severity: types.SeverityMedium,
					Title:    "GraphQL Mutations Vulnerable to CSRF",
					Description: "GraphQL mutations can be executed without CSRF tokens or origin validation. " +
						"This could allow attackers to perform unauthorized actions on behalf of authenticated users.",
					Evidence: fmt.Sprintf("Mutation executed successfully with malicious origin:\nMutation: %s\nOrigin: http://evil.com", mutation),
					Solution: "Implement CSRF protection:\n" +
						"1. Require CSRF tokens for all mutations\n" +
						"2. Validate Origin/Referer headers\n" +
						"3. Use SameSite cookies\n" +
						"4. Implement proper CORS policies\n" +
						"5. Consider using POST-only endpoints for mutations",
					Metadata: map[string]interface{}{
						"endpoint": endpoint,
						"mutation": mutation,
					},
				}
				findings = append(findings, finding)
				break // Only report once
			}
		}
	}

	return findings
}

func (s *graphQLScanner) testRateLimiting(ctx context.Context, endpoint string, options map[string]string) []types.Finding {
	findings := []types.Finding{}

	s.logger.Debug("Testing GraphQL rate limiting", "endpoint", endpoint)

	// Send multiple requests rapidly
	query := `{ __typename }`
	successCount := 0
	totalRequests := 30

	start := time.Now()
	for i := 0; i < totalRequests; i++ {
		payload := map[string]interface{}{
			"query": query,
		}

		jsonPayload, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonPayload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if s.config.UserAgent != "" {
			req.Header.Set("User-Agent", s.config.UserAgent)
		}

		if authHeader := options["auth_header"]; authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			successCount++
		}
		resp.Body.Close()

		// Don't delay between requests to test rate limiting
	}
	duration := time.Since(start)

	requestsPerSecond := float64(successCount) / duration.Seconds()

	if successCount >= int(float64(totalRequests)*0.8) && requestsPerSecond > 15 {
		severity := types.SeverityMedium
		if requestsPerSecond > 50 {
			severity = types.SeverityHigh
		}

		finding := types.Finding{
			Tool:     "graphql",
			Type:     "graphql_no_rate_limiting",
			Severity: severity,
			Title:    "GraphQL Endpoint Lacks Rate Limiting",
			Description: fmt.Sprintf("No rate limiting detected on GraphQL endpoint. Successfully sent %d/%d requests in %v (%.2f req/s). "+
				"This can lead to brute force attacks, resource exhaustion, and abuse.",
				successCount, totalRequests, duration, requestsPerSecond),
			Evidence: fmt.Sprintf("%d/%d requests succeeded at %.2f req/s over %v",
				successCount, totalRequests, requestsPerSecond, duration),
			Solution: "Implement rate limiting:\n" +
				"1. Add per-IP rate limiting\n" +
				"2. Implement query complexity-based limiting\n" +
				"3. Use token bucket or sliding window algorithms\n" +
				"4. Consider authenticated vs unauthenticated limits\n" +
				"5. Monitor and alert on abuse patterns",
			Metadata: map[string]interface{}{
				"endpoint":            endpoint,
				"successful_requests": successCount,
				"total_requests":      totalRequests,
				"requests_per_second": requestsPerSecond,
				"test_duration":       duration.String(),
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Helper functions

func (s *graphQLScanner) containsSensitiveInfo(message string) bool {
	sensitivePatterns := []string{
		"database", "sql", "mysql", "postgresql", "mongodb",
		"internal", "debug", "stacktrace", "exception",
		"password", "secret", "token", "key", "credential",
		"config", "configuration", "environment", "env",
	}

	messageLower := strings.ToLower(message)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(messageLower, pattern) {
			return true
		}
	}
	return false
}

func (s *graphQLScanner) containsFieldSuggestions(response string) bool {
	suggestionPatterns := []string{
		"did you mean", "suggestion", "available fields",
		"field does not exist", "cannot query field",
		"unknown field", "field not found", "similar field",
	}

	responseLower := strings.ToLower(response)
	for _, pattern := range suggestionPatterns {
		if strings.Contains(responseLower, pattern) {
			return true
		}
	}
	return false
}

func (s *graphQLScanner) containsAuthError(errors []GraphQLError) bool {
	authPatterns := []string{
		"unauthorized", "forbidden", "authentication", "permission",
		"access denied", "not allowed", "login required", "invalid token",
		"unauthenticated", "insufficient privileges",
	}

	for _, err := range errors {
		errorLower := strings.ToLower(err.Message)
		for _, pattern := range authPatterns {
			if strings.Contains(errorLower, pattern) {
				return true
			}
		}
	}
	return false
}

func (s *graphQLScanner) truncateResponse(response string, maxLength int) string {
	if len(response) <= maxLength {
		return response
	}
	return response[:maxLength] + "... [truncated]"
}
