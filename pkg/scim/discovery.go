package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"io"
	"net/http"
	"strings"
	"time"
)

// Discoverer handles SCIM endpoint discovery
type Discoverer struct {
	client *http.Client
	config *SCIMConfig
}

// NewDiscoverer creates a new SCIM endpoint discoverer
func NewDiscoverer(client *http.Client, config *SCIMConfig) *Discoverer {
	return &Discoverer{
		client: client,
		config: config,
	}
}

// DiscoverEndpoints discovers SCIM endpoints at the target URL
func (d *Discoverer) DiscoverEndpoints(ctx context.Context, baseURL string) ([]*SCIMEndpoint, error) {
	endpoints := []*SCIMEndpoint{}

	// Well-known SCIM paths to check
	scimPaths := []string{
		"/.well-known/scim-configuration",
		"/scim",
		"/scim/v2",
		"/scim/v1",
		"/api/scim",
		"/api/scim/v2",
		"/api/scim/v1",
		"/scim2",
		"/identity/scim",
		"/identity/scim/v2",
		"/Users",
		"/Groups",
		"/v2/Users",
		"/v2/Groups",
		"/api/v2/scim",
		"/services/scim",
		"/oauth/scim",
		"/sso/scim",
	}

	// Check each potential SCIM path with timeout handling
	for _, path := range scimPaths {
		select {
		case <-ctx.Done():
			return endpoints, ctx.Err()
		default:
			endpoint, err := d.testSCIMEndpoint(ctx, baseURL, path)
			if err != nil {
				continue // Skip failed endpoints
			}
			if endpoint != nil {
				endpoints = append(endpoints, endpoint)
			}
		}
	}

	// Additional discovery methods
	if len(endpoints) == 0 {
		// Try to discover through common patterns
		additionalEndpoints := d.discoverAdditionalEndpoints(ctx, baseURL)
		endpoints = append(endpoints, additionalEndpoints...)
	}

	// Enhance discovered endpoints with detailed information
	for _, endpoint := range endpoints {
		d.enrichEndpoint(ctx, endpoint)
	}

	return endpoints, nil
}

// testSCIMEndpoint tests if a specific path is a SCIM endpoint
func (d *Discoverer) testSCIMEndpoint(ctx context.Context, baseURL, path string) (*SCIMEndpoint, error) {
	fullURL := strings.TrimSuffix(baseURL, "/") + path

	// First, try to get service provider configuration
	endpoint := d.testServiceProviderConfig(ctx, fullURL)
	if endpoint != nil {
		return endpoint, nil
	}

	// Try to access Users resource
	endpoint = d.testUsersResource(ctx, fullURL)
	if endpoint != nil {
		return endpoint, nil
	}

	// Try to access Groups resource
	endpoint = d.testGroupsResource(ctx, fullURL)
	if endpoint != nil {
		return endpoint, nil
	}

	// Try to access Schemas resource
	endpoint = d.testSchemasResource(ctx, fullURL)
	if endpoint != nil {
		return endpoint, nil
	}

	return nil, fmt.Errorf("no SCIM endpoint found at %s", fullURL)
}

// testServiceProviderConfig tests for SCIM service provider configuration
func (d *Discoverer) testServiceProviderConfig(ctx context.Context, baseURL string) *SCIMEndpoint {
	configURLs := []string{
		baseURL + "/ServiceProviderConfig",
		baseURL + "/ServiceProviderConfigs",
		baseURL + "/v2/ServiceProviderConfig",
		baseURL + "/v1/ServiceProviderConfig",
	}

	for _, configURL := range configURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", d.config.UserAgent)
		req.Header.Set("Accept", "application/scim+json, application/json")

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			// Try to parse as SCIM ServiceProviderConfig
			var config map[string]interface{}
			if err := json.Unmarshal(body, &config); err != nil {
				continue
			}

			// Check if it looks like a SCIM ServiceProviderConfig
			if d.isServiceProviderConfig(config) {
				return d.buildEndpointFromConfig(baseURL, config)
			}
		}
	}

	return nil
}

// testUsersResource tests for SCIM Users resource
func (d *Discoverer) testUsersResource(ctx context.Context, baseURL string) *SCIMEndpoint {
	userURLs := []string{
		baseURL + "/Users",
		baseURL + "/v2/Users",
		baseURL + "/v1/Users",
	}

	for _, userURL := range userURLs {
		if d.testSCIMResource(ctx, userURL) {
			return &SCIMEndpoint{
				URL:          baseURL,
				Resources:    []string{"Users"},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// testGroupsResource tests for SCIM Groups resource
func (d *Discoverer) testGroupsResource(ctx context.Context, baseURL string) *SCIMEndpoint {
	groupURLs := []string{
		baseURL + "/Groups",
		baseURL + "/v2/Groups",
		baseURL + "/v1/Groups",
	}

	for _, groupURL := range groupURLs {
		if d.testSCIMResource(ctx, groupURL) {
			return &SCIMEndpoint{
				URL:          baseURL,
				Resources:    []string{"Groups"},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// testSchemasResource tests for SCIM Schemas resource
func (d *Discoverer) testSchemasResource(ctx context.Context, baseURL string) *SCIMEndpoint {
	schemaURLs := []string{
		baseURL + "/Schemas",
		baseURL + "/v2/Schemas",
		baseURL + "/v1/Schemas",
	}

	for _, schemaURL := range schemaURLs {
		if d.testSCIMResource(ctx, schemaURL) {
			return &SCIMEndpoint{
				URL:          baseURL,
				Resources:    []string{"Schemas"},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// testSCIMResource tests if a URL is a SCIM resource
func (d *Discoverer) testSCIMResource(ctx context.Context, resourceURL string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", resourceURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "application/scim+json, application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// Check response headers for SCIM indicators
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/scim+json") {
		return true
	}

	// Check for SCIM-specific response structure
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}

		return d.containsSCIMStructure(body)
	}

	return false
}

// containsSCIMStructure checks if response body contains SCIM structure
func (d *Discoverer) containsSCIMStructure(body []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return false
	}

	// Check for SCIM-specific fields
	scimFields := []string{
		"schemas",
		"totalResults",
		"Resources",
		"startIndex",
		"itemsPerPage",
		"scimType",
	}

	for _, field := range scimFields {
		if _, exists := data[field]; exists {
			return true
		}
	}

	// Check for SCIM schemas in the schemas array
	if schemas, ok := data["schemas"].([]interface{}); ok {
		for _, schema := range schemas {
			if schemaStr, ok := schema.(string); ok {
				if strings.Contains(schemaStr, "urn:ietf:params:scim") {
					return true
				}
			}
		}
	}

	return false
}

// isServiceProviderConfig checks if the response is a SCIM ServiceProviderConfig
func (d *Discoverer) isServiceProviderConfig(config map[string]interface{}) bool {
	// Check for ServiceProviderConfig specific fields
	configFields := []string{
		"patch",
		"bulk",
		"filter",
		"changePassword",
		"sort",
		"etag",
		"authenticationSchemes",
	}

	fieldCount := 0
	for _, field := range configFields {
		if _, exists := config[field]; exists {
			fieldCount++
		}
	}

	// If at least 3 ServiceProviderConfig fields are present, consider it valid
	return fieldCount >= 3
}

// buildEndpointFromConfig builds a SCIM endpoint from ServiceProviderConfig
func (d *Discoverer) buildEndpointFromConfig(baseURL string, config map[string]interface{}) *SCIMEndpoint {
	endpoint := &SCIMEndpoint{
		URL:          baseURL,
		Resources:    []string{},
		Schemas:      []string{},
		Operations:   []string{},
		DiscoveredAt: time.Now(),
	}

	// Extract version if available
	if schemas, ok := config["schemas"].([]interface{}); ok {
		for _, schema := range schemas {
			if schemaStr, ok := schema.(string); ok {
				endpoint.Schemas = append(endpoint.Schemas, schemaStr)
				if strings.Contains(schemaStr, "2.0") {
					endpoint.Version = "2.0"
				} else if strings.Contains(schemaStr, "1.1") {
					endpoint.Version = "1.1"
				}
			}
		}
	}

	// Extract supported features
	if bulk, ok := config["bulk"].(map[string]interface{}); ok {
		if supported, ok := bulk["supported"].(bool); ok {
			endpoint.BulkSupported = supported
		}
	}

	if filter, ok := config["filter"].(map[string]interface{}); ok {
		if supported, ok := filter["supported"].(bool); ok {
			endpoint.FilterSupported = supported
		}
	}

	if sort, ok := config["sort"].(map[string]interface{}); ok {
		if supported, ok := sort["supported"].(bool); ok {
			endpoint.SortSupported = supported
		}
	}

	if etag, ok := config["etag"].(map[string]interface{}); ok {
		if supported, ok := etag["supported"].(bool); ok {
			endpoint.ETagSupported = supported
		}
	}

	// Extract authentication schemes
	if authSchemes, ok := config["authenticationSchemes"].([]interface{}); ok {
		for _, scheme := range authSchemes {
			if schemeMap, ok := scheme.(map[string]interface{}); ok {
				if authType, ok := schemeMap["type"].(string); ok {
					endpoint.AuthType = authType
					break
				}
			}
		}
	}

	// Default resources
	endpoint.Resources = []string{"Users", "Groups", "Schemas", "ResourceTypes", "ServiceProviderConfig"}

	return endpoint
}

// enrichEndpoint enriches endpoint information with additional details
func (d *Discoverer) enrichEndpoint(ctx context.Context, endpoint *SCIMEndpoint) {
	// Test resource types
	d.discoverResourceTypes(ctx, endpoint)

	// Test supported operations
	d.discoverSupportedOperations(ctx, endpoint)

	// Test schemas
	d.discoverSchemas(ctx, endpoint)
}

// discoverResourceTypes discovers available resource types
func (d *Discoverer) discoverResourceTypes(ctx context.Context, endpoint *SCIMEndpoint) {
	resourceTypesURL := endpoint.URL + "/ResourceTypes"

	req, err := http.NewRequestWithContext(ctx, "GET", resourceTypesURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "application/scim+json, application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}

		var resourceTypes map[string]interface{}
		if err := json.Unmarshal(body, &resourceTypes); err != nil {
			return
		}

		// Parse resource types
		if resources, ok := resourceTypes["Resources"].([]interface{}); ok {
			endpoint.Resources = []string{}
			for _, resource := range resources {
				if resourceMap, ok := resource.(map[string]interface{}); ok {
					if name, ok := resourceMap["name"].(string); ok {
						endpoint.Resources = append(endpoint.Resources, name)
					}
				}
			}
		}
	}
}

// discoverSupportedOperations discovers supported operations
func (d *Discoverer) discoverSupportedOperations(ctx context.Context, endpoint *SCIMEndpoint) {
	operations := []string{}

	// Test common operations on Users resource
	userURL := endpoint.URL + "/Users"
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

	for _, method := range methods {
		req, err := http.NewRequestWithContext(ctx, method, userURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", d.config.UserAgent)
		req.Header.Set("Accept", "application/scim+json")

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		httpclient.CloseBody(resp)

		// If not 404/405, the method is likely supported
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			operations = append(operations, method)
		}
	}

	endpoint.Operations = operations
}

// discoverSchemas discovers available schemas
func (d *Discoverer) discoverSchemas(ctx context.Context, endpoint *SCIMEndpoint) {
	schemasURL := endpoint.URL + "/Schemas"

	req, err := http.NewRequestWithContext(ctx, "GET", schemasURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "application/scim+json, application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}

		var schemas map[string]interface{}
		if err := json.Unmarshal(body, &schemas); err != nil {
			return
		}

		// Parse schemas
		if resources, ok := schemas["Resources"].([]interface{}); ok {
			endpoint.Schemas = []string{}
			for _, resource := range resources {
				if resourceMap, ok := resource.(map[string]interface{}); ok {
					if id, ok := resourceMap["id"].(string); ok {
						endpoint.Schemas = append(endpoint.Schemas, id)
					}
				}
			}
		}
	}
}

// discoverAdditionalEndpoints discovers additional endpoints through various methods
func (d *Discoverer) discoverAdditionalEndpoints(ctx context.Context, baseURL string) []*SCIMEndpoint {
	endpoints := []*SCIMEndpoint{}

	// Try common subdirectories
	subDirs := []string{
		"/identity",
		"/auth",
		"/oauth",
		"/sso",
		"/api",
		"/v1",
		"/v2",
		"/services",
		"/management",
		"/admin",
	}

	for _, subDir := range subDirs {
		subURL := strings.TrimSuffix(baseURL, "/") + subDir
		subEndpoints, _ := d.DiscoverEndpoints(ctx, subURL)
		endpoints = append(endpoints, subEndpoints...)
	}

	return endpoints
}
