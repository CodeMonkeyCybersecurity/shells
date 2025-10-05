package cloud

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// AzureDiscovery discovers Azure assets
type AzureDiscovery struct {
	client *http.Client
	logger *logger.Logger
}

// NewAzureDiscovery creates a new Azure discovery client
func NewAzureDiscovery(logger *logger.Logger) *AzureDiscovery {
	return &AzureDiscovery{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// BlobContainer represents an Azure Blob Storage container
type BlobContainer struct {
	AccountName   string
	ContainerName string
	URL           string
	IsPublic      bool
	Exists        bool
	HasListing    bool
	Blobs         []BlobItem
}

// BlobItem represents a blob in Azure storage
type BlobItem struct {
	Name         string
	Size         int64
	LastModified time.Time
	ContentType  string
}

// DiscoverBlobContainers discovers Azure Blob Storage containers
func (a *AzureDiscovery) DiscoverBlobContainers(ctx context.Context, domain string) ([]BlobContainer, error) {
	var containers []BlobContainer

	baseName := extractBaseName(domain)

	// Generate potential storage account names
	accountNames := a.generateStorageAccountNames(baseName, domain)

	// Common container names
	containerNames := []string{
		"$root", "$web", "backup", "backups", "data", "files", "uploads",
		"images", "media", "documents", "public", "private", "static",
		"assets", "content", "archive", "logs", "temp", "cache",
	}

	// Check each combination
	for _, accountName := range accountNames {
		for _, containerName := range containerNames {
			container := a.checkBlobContainer(ctx, accountName, containerName)
			if container != nil && container.Exists {
				containers = append(containers, *container)
			}
		}
	}

	a.logger.Info("Azure Blob container discovery completed",
		"domain", domain,
		"accounts_checked", len(accountNames),
		"containers_found", len(containers))

	return containers, nil
}

// generateStorageAccountNames generates potential Azure storage account names
func (a *AzureDiscovery) generateStorageAccountNames(baseName, domain string) []string {
	var names []string

	// Azure storage account names must be 3-24 chars, lowercase alphanumeric only
	cleanBase := strings.ToLower(regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(baseName, ""))
	if len(cleanBase) > 20 {
		cleanBase = cleanBase[:20]
	}

	patterns := []string{
		"%s",
		"%sstorage",
		"%sstore",
		"%sblob",
		"%sdata",
		"%sfiles",
		"%sbackup",
		"%sassets",
		"%sstatic",
		"%smedia",
		"%simages",
		"%scontent",
		"%sarchive",
		"%spublic",
		"%sprivate",
		"%sdev",
		"%sstaging",
		"%sprod",
		"%stest",
		"storage%s",
		"blob%s",
		"data%s",
		"files%s",
		"backup%s",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, cleanBase)
		if isValidStorageAccountName(name) {
			names = append(names, name)
		}
	}

	// Try with numbers
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("%s%d", cleanBase, i)
		if isValidStorageAccountName(name) {
			names = append(names, name)
		}
	}

	// Remove duplicates
	uniqueNames := make(map[string]bool)
	var result []string
	for _, name := range names {
		if !uniqueNames[name] {
			uniqueNames[name] = true
			result = append(result, name)
		}
	}

	return result
}

// checkBlobContainer checks if an Azure blob container exists
func (a *AzureDiscovery) checkBlobContainer(ctx context.Context, accountName, containerName string) *BlobContainer {
	container := &BlobContainer{
		AccountName:   accountName,
		ContainerName: containerName,
		URL:           fmt.Sprintf("https://%s.blob.core.windows.net/%s", accountName, containerName),
	}

	// Try to list blobs in the container
	listURL := fmt.Sprintf("%s?restype=container&comp=list", container.URL)
	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return container
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return container
	}
	defer httpclient.CloseBody(resp)

	switch resp.StatusCode {
	case 200:
		// Container exists and is publicly accessible
		container.Exists = true
		container.IsPublic = true
		container.HasListing = true

		// Parse blob listing
		var enumeration blobEnumerationResults
		if err := xml.NewDecoder(resp.Body).Decode(&enumeration); err == nil {
			for _, blob := range enumeration.Blobs {
				container.Blobs = append(container.Blobs, BlobItem{
					Name:         blob.Name,
					Size:         blob.Properties.ContentLength,
					LastModified: blob.Properties.LastModified,
					ContentType:  blob.Properties.ContentType,
				})
			}
		}

	case 403:
		// Container exists but is private
		container.Exists = true
		container.IsPublic = false

	case 404:
		// Try without list permissions (check if container exists)
		headReq, _ := http.NewRequestWithContext(ctx, "HEAD", container.URL, nil)
		if headResp, err := a.client.Do(headReq); err == nil {
			defer headResp.Body.Close()
			if headResp.StatusCode == 200 || headResp.StatusCode == 403 {
				container.Exists = true
				container.IsPublic = headResp.StatusCode == 200
			}
		}
	}

	return container
}

// blobEnumerationResults represents Azure blob listing XML
type blobEnumerationResults struct {
	XMLName xml.Name `xml:"EnumerationResults"`
	Blobs   []struct {
		Name       string `xml:"Name"`
		Properties struct {
			LastModified  time.Time `xml:"Last-Modified"`
			ContentLength int64     `xml:"Content-Length"`
			ContentType   string    `xml:"Content-Type"`
		} `xml:"Properties"`
	} `xml:"Blobs>Blob"`
}

// DiscoverAzureApps discovers Azure App Service applications
func (a *AzureDiscovery) DiscoverAzureApps(ctx context.Context, domain string) ([]AzureApp, error) {
	var apps []AzureApp

	baseName := extractBaseName(domain)

	// Azure App Service URL patterns
	appNames := []string{
		baseName,
		baseName + "-app",
		baseName + "-api",
		baseName + "-web",
		baseName + "-dev",
		baseName + "-staging",
		baseName + "-prod",
		"app-" + baseName,
		"api-" + baseName,
		"web-" + baseName,
	}

	for _, appName := range appNames {
		// Check .azurewebsites.net
		azureURL := fmt.Sprintf("https://%s.azurewebsites.net", appName)
		if a.checkAzureApp(ctx, azureURL) {
			apps = append(apps, AzureApp{
				Name: appName,
				URL:  azureURL,
				Type: "App Service",
			})
		}

		// Check .azurefd.net (Azure Front Door)
		afdURL := fmt.Sprintf("https://%s.azurefd.net", appName)
		if a.checkAzureApp(ctx, afdURL) {
			apps = append(apps, AzureApp{
				Name: appName,
				URL:  afdURL,
				Type: "Front Door",
			})
		}

		// Check .azureedge.net (Azure CDN)
		cdnURL := fmt.Sprintf("https://%s.azureedge.net", appName)
		if a.checkAzureApp(ctx, cdnURL) {
			apps = append(apps, AzureApp{
				Name: appName,
				URL:  cdnURL,
				Type: "CDN",
			})
		}
	}

	return apps, nil
}

// AzureApp represents an Azure application
type AzureApp struct {
	Name string
	URL  string
	Type string
}

// checkAzureApp checks if an Azure app exists
func (a *AzureDiscovery) checkAzureApp(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	return resp.StatusCode != 404
}

// DiscoverAzureContainerRegistry discovers Azure Container Registry repositories
func (a *AzureDiscovery) DiscoverAzureContainerRegistry(ctx context.Context, domain string) ([]ContainerRegistry, error) {
	var registries []ContainerRegistry

	baseName := extractBaseName(domain)
	cleanBase := strings.ToLower(regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(baseName, ""))

	// ACR names
	registryNames := []string{
		cleanBase,
		cleanBase + "acr",
		cleanBase + "registry",
		cleanBase + "cr",
		"acr" + cleanBase,
		"registry" + cleanBase,
		"cr" + cleanBase,
	}

	for _, regName := range registryNames {
		if isValidACRName(regName) {
			registry := a.checkContainerRegistry(ctx, regName)
			if registry != nil && registry.Exists {
				registries = append(registries, *registry)
			}
		}
	}

	return registries, nil
}

// ContainerRegistry represents an Azure Container Registry
type ContainerRegistry struct {
	Name         string
	URL          string
	Exists       bool
	IsPublic     bool
	Repositories []string
}

// checkContainerRegistry checks if an ACR exists
func (a *AzureDiscovery) checkContainerRegistry(ctx context.Context, registryName string) *ContainerRegistry {
	registry := &ContainerRegistry{
		Name: registryName,
		URL:  fmt.Sprintf("https://%s.azurecr.io", registryName),
	}

	// Check v2 API
	catalogURL := fmt.Sprintf("%s/v2/_catalog", registry.URL)
	req, err := http.NewRequestWithContext(ctx, "GET", catalogURL, nil)
	if err != nil {
		return registry
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return registry
	}
	defer httpclient.CloseBody(resp)

	switch resp.StatusCode {
	case 200:
		// Registry exists and is public
		registry.Exists = true
		registry.IsPublic = true

		// Parse repository list
		var catalog struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&catalog); err == nil {
			registry.Repositories = catalog.Repositories
		}

	case 401, 403:
		// Registry exists but requires authentication
		registry.Exists = true
		registry.IsPublic = false

	case 404:
		// Check if registry exists at all
		baseReq, _ := http.NewRequestWithContext(ctx, "HEAD", registry.URL, nil)
		if baseResp, err := a.client.Do(baseReq); err == nil {
			defer baseResp.Body.Close()
			registry.Exists = baseResp.StatusCode != 404
		}
	}

	return registry
}

// DiscoverAzureFunctions discovers Azure Functions
func (a *AzureDiscovery) DiscoverAzureFunctions(ctx context.Context, domain string) ([]AzureFunction, error) {
	var functions []AzureFunction

	baseName := extractBaseName(domain)

	// Function app names
	funcNames := []string{
		baseName,
		baseName + "-func",
		baseName + "-function",
		baseName + "-api",
		baseName + "-fn",
		"func-" + baseName,
		"function-" + baseName,
		"fn-" + baseName,
	}

	for _, funcName := range funcNames {
		funcURL := fmt.Sprintf("https://%s.azurewebsites.net", funcName)
		if a.checkAzureFunction(ctx, funcURL) {
			functions = append(functions, AzureFunction{
				Name: funcName,
				URL:  funcURL,
			})
		}
	}

	return functions, nil
}

// AzureFunction represents an Azure Function app
type AzureFunction struct {
	Name string
	URL  string
}

// checkAzureFunction checks if an Azure Function exists
func (a *AzureDiscovery) checkAzureFunction(ctx context.Context, url string) bool {
	// Azure Functions often have /api/ endpoints
	apiURL := url + "/api/"
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// Functions typically return 401 or custom response, not 404
	return resp.StatusCode != 404
}

// DiscoverKeyVaults attempts to discover Azure Key Vaults
func (a *AzureDiscovery) DiscoverKeyVaults(ctx context.Context, domain string) ([]KeyVault, error) {
	var vaults []KeyVault

	baseName := extractBaseName(domain)
	cleanBase := strings.ToLower(regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(baseName, ""))

	// Key Vault names
	vaultNames := []string{
		cleanBase,
		cleanBase + "-kv",
		cleanBase + "-vault",
		cleanBase + "-keyvault",
		"kv-" + cleanBase,
		"vault-" + cleanBase,
		"keyvault-" + cleanBase,
	}

	for _, vaultName := range vaultNames {
		if isValidKeyVaultName(vaultName) {
			vault := a.checkKeyVault(ctx, vaultName)
			if vault != nil && vault.Exists {
				vaults = append(vaults, *vault)
			}
		}
	}

	return vaults, nil
}

// KeyVault represents an Azure Key Vault
type KeyVault struct {
	Name   string
	URL    string
	Exists bool
}

// checkKeyVault checks if a Key Vault exists
func (a *AzureDiscovery) checkKeyVault(ctx context.Context, vaultName string) *KeyVault {
	vault := &KeyVault{
		Name: vaultName,
		URL:  fmt.Sprintf("https://%s.vault.azure.net", vaultName),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", vault.URL, nil)
	if err != nil {
		return vault
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return vault
	}
	defer httpclient.CloseBody(resp)

	// Key Vaults return 401/403 if they exist
	vault.Exists = resp.StatusCode == 401 || resp.StatusCode == 403

	return vault
}

// Helper functions

func isValidStorageAccountName(name string) bool {
	// Azure storage account naming rules
	if len(name) < 3 || len(name) > 24 {
		return false
	}

	// Must be lowercase alphanumeric only
	matched, _ := regexp.MatchString(`^[a-z0-9]+$`, name)
	return matched
}

func isValidACRName(name string) bool {
	// ACR naming rules: 5-50 chars, alphanumeric only
	if len(name) < 5 || len(name) > 50 {
		return false
	}

	matched, _ := regexp.MatchString(`^[a-zA-Z0-9]+$`, name)
	return matched
}

func isValidKeyVaultName(name string) bool {
	// Key Vault naming: 3-24 chars, alphanumeric and hyphens
	if len(name) < 3 || len(name) > 24 {
		return false
	}

	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$`, name)
	return matched
}
