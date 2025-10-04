# HTTP Client Standardization Plan

## Problem

78 files create raw `http.Client{}` instances with no:
- Timeouts
- Retries
- Rate limiting
- User-Agent
- TLS configuration
- Connection pooling limits

## Solution

Use the existing `pkg/http/client.go` SecureClient everywhere.

## Migration Steps

### Phase 1: Enhance SecureClient (DONE)

File: `pkg/http/client.go`

Already has:
- ✅ Proper TLS config (TLS 1.2+)
- ✅ Timeouts (configurable)
- ✅ Connection pooling (100 max, 10 per host)
- ✅ User-Agent setting
- ✅ Redirect limiting (max 10)
- ✅ Context support

Need to add:
- ❌ Retry logic with exponential backoff
- ❌ Rate limiting integration
- ❌ Request logging/tracing

### Phase 2: Create Default Client Factory

```go
// pkg/http/factory.go
package http

import (
    "time"
    "github.com/CodeMonkeyCybersecurity/shells/internal/ratelimit"
)

// DefaultClient creates a client with standard bug bounty settings
func DefaultClient() *SecureClient {
    return NewSecureClient(30 * time.Second)
}

// QuickClient creates a client for fast scans
func QuickClient() *SecureClient {
    return NewSecureClient(5 * time.Second)
}

// SlowClient creates a client for comprehensive scans
func SlowClient() *SecureClient {
    return NewSecureClient(60 * time.Second)
}

// RateLimitedClient wraps SecureClient with rate limiting
type RateLimitedClient struct {
    *SecureClient
    limiter *ratelimit.Limiter
}

func NewRateLimitedClient(timeout time.Duration, limiter *ratelimit.Limiter) *RateLimitedClient {
    return &RateLimitedClient{
        SecureClient: NewSecureClient(timeout),
        limiter:      limiter,
    }
}

// Get wraps parent Get with rate limiting
func (c *RateLimitedClient) Get(ctx context.Context, url string) (*http.Response, error) {
    if err := c.limiter.Wait(ctx, url); err != nil {
        return nil, err
    }
    return c.SecureClient.Get(ctx, url)
}

// Similar for Post, Put, etc.
```

### Phase 3: Replace Raw Clients (78 files)

**Pattern to find:**
```go
// BAD
client := &http.Client{}
client := http.DefaultClient
client := &http.Client{Timeout: ...}
```

**Replace with:**
```go
// GOOD
client := httputil.DefaultClient()

// Or for specific needs:
client := httputil.QuickClient()
client := httputil.NewSecureClient(30 * time.Second)
```

**Files to update (Priority Order):**

**High Priority** (Core scanners - 10 files):
1. `pkg/scim/scanner.go`
2. `pkg/auth/saml/scanner.go`
3. `pkg/auth/oauth2/scanner.go`
4. `pkg/auth/webauthn/scanner.go`
5. `pkg/smuggling/scanner.go`
6. `pkg/scanners/intelligent.go`
7. `pkg/logic/core/workflow.go`
8. `internal/plugins/nuclei/nuclei.go`
9. `internal/plugins/nmap/nmap.go`
10. `internal/plugins/api/graphql.go`

**Medium Priority** (Discovery - 20 files):
11-30. All files in `pkg/discovery/*`

**Low Priority** (Everything else - 48 files):
31-78. Infrastructure, passive, intel, etc.

### Phase 4: Add Retry Logic

```go
// pkg/http/retry.go
package http

import (
    "context"
    "math"
    "net/http"
    "time"
)

type RetryConfig struct {
    MaxAttempts int
    InitialDelay time.Duration
    MaxDelay time.Duration
    Multiplier float64
}

func DefaultRetryConfig() RetryConfig {
    return RetryConfig{
        MaxAttempts: 3,
        InitialDelay: 1 * time.Second,
        MaxDelay: 10 * time.Second,
        Multiplier: 2.0,
    }
}

// DoWithRetry executes request with exponential backoff
func (c *SecureClient) DoWithRetry(ctx context.Context, req *http.Request, cfg RetryConfig) (*http.Response, error) {
    var lastErr error
    delay := cfg.InitialDelay

    for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
        if attempt > 0 {
            select {
            case <-time.After(delay):
            case <-ctx.Done():
                return nil, ctx.Err()
            }

            // Exponential backoff
            delay = time.Duration(float64(delay) * cfg.Multiplier)
            if delay > cfg.MaxDelay {
                delay = cfg.MaxDelay
            }
        }

        resp, err := c.client.Do(req)
        if err == nil {
            // Success or non-retryable HTTP error
            if resp.StatusCode < 500 {
                return resp, nil
            }
            resp.Body.Close()
        }

        lastErr = err
    }

    return nil, lastErr
}
```

### Phase 5: Testing

Create tests for:
- ❌ Timeout enforcement
- ❌ Retry logic
- ❌ Rate limiting integration
- ❌ TLS validation
- ❌ Redirect handling
- ❌ Connection pooling

## Implementation Timeline

**Week 1:**
- ✅ Enhance SecureClient with retries
- ✅ Create factory functions
- ✅ Write comprehensive tests

**Week 2:**
- ✅ Update 10 high-priority scanner files
- ✅ Test scanners still work
- ✅ Verify performance impact

**Week 3:**
- ✅ Update 20 discovery files
- ✅ Test discovery still works

**Week 4:**
- ✅ Update remaining 48 files
- ✅ Remove all raw http.Client usage
- ✅ Add linter rule to prevent future raw clients

## Verification

After migration, run:

```bash
# Should find ZERO raw http.Client instances
grep -r "http.Client{" --include="*.go" pkg/ internal/ cmd/

# Should find ZERO DefaultClient usage
grep -r "http.DefaultClient" --include="*.go" pkg/ internal/ cmd/

# All tests should pass
go test ./...

# Scans should complete successfully
./shells --quick example.com
```

## Benefits

After migration:
- ✅ All HTTP requests have timeouts
- ✅ Failed requests automatically retry
- ✅ Consistent User-Agent across all scanners
- ✅ Proper TLS configuration everywhere
- ✅ Connection pooling prevents resource exhaustion
- ✅ Rate limiting prevents IP bans
- ✅ Easier to add instrumentation/logging
- ✅ Single place to update HTTP behavior

## Risk Mitigation

- Test each file after migration
- Keep old client as fallback during transition
- Monitor error rates after deployment
- Have rollback plan ready
