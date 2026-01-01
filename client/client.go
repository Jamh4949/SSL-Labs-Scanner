// Package client provides an HTTP client for the SSL Labs API v4.
// It handles authentication, rate limiting, retries with exponential backoff,
// and proper context cancellation for graceful shutdown.
//
// Reference: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssllabs-scanner/models"
)

// Configuration constants for the SSL Labs API client.
const (
	// BaseURL is the base URL for SSL Labs API v4.
	BaseURL = "https://api.ssllabs.com/api/v4"

	// Version is the client version used in User-Agent header.
	Version = "1.0.0"

	// Polling intervals as recommended by the official documentation.
	// Use shorter intervals before IN_PROGRESS, longer during active analysis.
	InitialPollInterval = 5 * time.Second  // Before status becomes IN_PROGRESS
	ActivePollInterval  = 10 * time.Second // During IN_PROGRESS status

	// Retry configuration for temporary errors.
	MaxRetries          = 3               // Maximum HTTP retry attempts for 503/529 errors
	MaxNetRetries       = 2               // Maximum retries for transient network errors
	RetryJitterFraction = 0.2             // ±20% random variation to prevent thundering herd
	NetRetryDelay       = 5 * time.Second // Base delay for network error retries

	// Retry delays for specific HTTP error codes.
	// NOTE: These are reduced for demo purposes. Production should use:
	// - 503: 15 minutes (official recommendation)
	// - 529: 30 minutes (official recommendation)
	RetryDelay503 = 30 * time.Second // Service Unavailable retry delay
	RetryDelay529 = 45 * time.Second // Overloaded retry delay

	// MaxBodySize limits response body size to prevent memory exhaustion attacks.
	// If a malicious server sends an infinite response, we stop reading at this limit.
	MaxBodySize = 10 * 1024 * 1024 // 10 MB
)

// RateLimitInfo contains rate limiting information from API response headers.
// These values are extracted from X-Max-Assessments and X-Current-Assessments headers.
type RateLimitInfo struct {
	MaxAssessments     int // Maximum concurrent assessments allowed
	CurrentAssessments int // Number of assessments currently in progress
}

// Client is the HTTP client for interacting with the SSL Labs API.
// It is safe for concurrent use after initialization.
type Client struct {
	httpClient *http.Client // Underlying HTTP client with timeout and transport config
	email      string       // Registered email for API authentication
	baseURL    string       // API base URL (allows testing with mock servers)
	userAgent  string       // User-Agent header value

	// rng is a dedicated random number generator with its own seed.
	// Using a dedicated RNG avoids global state issues with math/rand in Go < 1.20.
	rng *rand.Rand

	// Thread-safe rate limit tracking.
	// Uses RWMutex because reads are frequent but writes are rare.
	rlMu          sync.RWMutex  // Protects lastRateLimit
	lastRateLimit RateLimitInfo // Most recent rate limit info from API
}

// New creates a new SSL Labs API client with the given registered email.
// The email must be pre-registered with SSL Labs (see README.md).
func New(email string) *Client {
	// Create a dedicated RNG with unique seed to avoid global state issues.
	// This is important for jitter calculations in concurrent scenarios.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Configure HTTP transport with connection pooling and proxy support.
	// ProxyFromEnvironment respects HTTP_PROXY and HTTPS_PROXY env vars.
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment, // Support corporate proxies
		MaxIdleConns:      10,                        // Connection pool size
		IdleConnTimeout:   30 * time.Second,          // Cleanup idle connections
		DisableKeepAlives: false,                     // Reuse connections for efficiency
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:   60 * time.Second, // Global timeout per request
			Transport: transport,
		},
		email:     email,
		baseURL:   BaseURL,
		userAgent: fmt.Sprintf("SSLLabsScanner/%s (Go)", Version),
		rng:       rng,
	}
}

// GetRateLimitInfo returns the most recent rate limiting information.
// This method is thread-safe and can be called concurrently.
func (c *Client) GetRateLimitInfo() RateLimitInfo {
	c.rlMu.RLock()
	defer c.rlMu.RUnlock()
	return c.lastRateLimit
}

// updateRateLimit updates the rate limiting information from response headers.
// This method is thread-safe and uses exclusive locking for writes.
func (c *Client) updateRateLimit(max, current int) {
	c.rlMu.Lock()
	defer c.rlMu.Unlock()
	if max > 0 {
		c.lastRateLimit.MaxAssessments = max
	}
	if current >= 0 {
		c.lastRateLimit.CurrentAssessments = current
	}
}

// ValidateEmail checks if the email is acceptable for SSL Labs registration.
// SSL Labs blocks free email providers (Gmail, Yahoo, Hotmail, etc.).
// Note: This is heuristic validation; SSL Labs may change blocked domains.
func ValidateEmail(email string) (warnings []string) {
	lower := strings.ToLower(email)
	blockedDomains := []string{"@gmail.", "@yahoo.", "@hotmail.", "@outlook.com", "@live.com"}

	for _, domain := range blockedDomains {
		if strings.Contains(lower, domain) {
			warnings = append(warnings, fmt.Sprintf(
				"⚠️  Warning: SSL Labs does not allow emails from free services (%s). Registration may fail.",
				domain))
			break
		}
	}

	if !strings.Contains(email, "@") {
		warnings = append(warnings, "⚠️  Warning: Email appears invalid (missing @)")
	}

	return warnings
}

// APIError represents a structured error response from the SSL Labs API.
// It implements the error interface for seamless error handling.
type APIError struct {
	StatusCode int                  // HTTP status code
	RawBody    string               // Raw response body for debugging
	Errors     []models.ErrorDetail // Parsed error details from JSON response
}

// Error implements the error interface.
// It formats the error message including all error details if available.
func (e *APIError) Error() string {
	if len(e.Errors) > 0 {
		var msgs []string
		for _, err := range e.Errors {
			if err.Field != "" {
				msgs = append(msgs, fmt.Sprintf("%s: %s", err.Field, err.Message))
			} else {
				msgs = append(msgs, err.Message)
			}
		}
		return fmt.Sprintf("error %d: %s", e.StatusCode, strings.Join(msgs, "; "))
	}
	return fmt.Sprintf("error %d: %s", e.StatusCode, e.RawBody)
}

// sleepWithContext pauses execution for the specified duration while respecting
// context cancellation. Returns ctx.Err() if the context is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// addJitter adds random variation (±20%) to a delay duration.
// This prevents the "thundering herd" problem where many clients
// retry at exactly the same time after receiving the same error.
func (c *Client) addJitter(d time.Duration) time.Duration {
	jitter := float64(d) * RetryJitterFraction
	offset := (c.rng.Float64() * 2 * jitter) - jitter
	return d + time.Duration(offset)
}

// parseRetryAfter parses the Retry-After HTTP header.
// It supports both formats: seconds (e.g., "120") and HTTP-date.
// Returns 0 if the header is empty or cannot be parsed.
func (c *Client) parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}

	// Try parsing as seconds
	if secs, err := strconv.Atoi(value); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}

	// Try parsing as HTTP-date (RFC 7231)
	if t, err := http.ParseTime(value); err == nil {
		delay := time.Until(t)
		if delay > 0 {
			return delay
		}
	}

	return 0
}

// isTemporaryNetError determines if a network error is transient and worth retrying.
// It checks for timeout errors, temporary errors, and common transient error patterns.
func isTemporaryNetError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a net.Error with Timeout() or Temporary() methods
	var netErr net.Error
	if ok := errors.As(err, &netErr); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	// Check for common transient error patterns in error message
	errStr := err.Error()
	transientPatterns := []string{
		"connection reset",
		"connection refused",
		"no such host",
		"EOF",
		"timeout",
		"temporary failure",
	}
	for _, pattern := range transientPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}

// doRequest executes an HTTP request with proper headers, retry logic, and rate limiting.
// It handles transient network errors, HTTP status codes (429, 503, 529), and respects
// context cancellation for graceful shutdown.
func (c *Client) doRequest(ctx context.Context, endpoint string, params url.Values) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s", c.baseURL, endpoint)
	if len(params) > 0 {
		reqURL = fmt.Sprintf("%s?%s", reqURL, params.Encode())
	}

	var lastErr error
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		// Check for context cancellation before each retry attempt
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %w", err)
		}

		// Set required and recommended headers
		req.Header.Set("email", c.email)             // SSL Labs authentication
		req.Header.Set("User-Agent", c.userAgent)    // Client identification
		req.Header.Set("Accept", "application/json") // Expected response format

		// Execute request with retries for transient network errors
		var resp *http.Response
		var body []byte

		for netAttempt := 0; netAttempt <= MaxNetRetries; netAttempt++ {
			resp, err = c.httpClient.Do(req)
			if err == nil {
				break
			}

			// If transient error and retries remaining, wait and retry
			if isTemporaryNetError(err) && netAttempt < MaxNetRetries {
				delay := c.addJitter(NetRetryDelay)
				lastErr = fmt.Errorf("transient network error (attempt %d/%d): %w", netAttempt+1, MaxNetRetries+1, err)
				if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
					return nil, sleepErr
				}
				// Recreate request as the previous one may be "used"
				req, _ = http.NewRequestWithContext(ctx, "GET", reqURL, nil)
				req.Header.Set("email", c.email)
				req.Header.Set("User-Agent", c.userAgent)
				req.Header.Set("Accept", "application/json")
				continue
			}

			return nil, fmt.Errorf("request error: %w", err)
		}

		if resp == nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("unknown error: nil response")
		}

		// Limit body reading to prevent memory exhaustion attacks
		limitedReader := io.LimitReader(resp.Body, MaxBodySize+1)
		body, err = io.ReadAll(limitedReader)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("error reading response: %w", err)
		}
		if len(body) > MaxBodySize {
			return nil, fmt.Errorf("response too large (>%d bytes)", MaxBodySize)
		}

		// Extract rate limiting headers (thread-safe update)
		maxVal, currVal := -1, -1
		if maxStr := resp.Header.Get("X-Max-Assessments"); maxStr != "" {
			if max, err := strconv.Atoi(maxStr); err == nil {
				maxVal = max
			}
		}
		if currStr := resp.Header.Get("X-Current-Assessments"); currStr != "" {
			if curr, err := strconv.Atoi(currStr); err == nil {
				currVal = curr
			}
		}
		c.updateRateLimit(maxVal, currVal)

		// Handle HTTP status codes according to API documentation
		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil

		case http.StatusBadRequest: // 400: Invalid parameters
			return nil, c.parseAPIError(400, body)

		case 429: // Too Many Requests: check Retry-After header
			if attempt < MaxRetries {
				if delay := c.parseRetryAfter(resp.Header.Get("Retry-After")); delay > 0 {
					lastErr = fmt.Errorf("error 429: too many requests, waiting %v", delay)
					if err := sleepWithContext(ctx, c.addJitter(delay)); err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, &APIError{
				StatusCode: 429,
				RawBody:    "too many requests - reduce concurrency and wait",
			}

		case 441: // Not Authorized: email not registered
			return nil, &APIError{
				StatusCode: 441,
				RawBody:    "not authorized - must register email first",
			}

		case http.StatusInternalServerError: // 500: Severe error, don't retry
			return nil, &APIError{StatusCode: 500, RawBody: string(body)}

		case http.StatusServiceUnavailable: // 503: Service unavailable, retry with delay
			if attempt < MaxRetries {
				delay := c.addJitter(RetryDelay503)
				lastErr = fmt.Errorf("error 503: service unavailable, retrying in %v", delay)
				if err := sleepWithContext(ctx, delay); err != nil {
					return nil, err
				}
				continue
			}
			return nil, &APIError{StatusCode: 503, RawBody: "service unavailable after retries"}

		case 529: // Overloaded: retry with longer delay
			if attempt < MaxRetries {
				delay := c.addJitter(RetryDelay529)
				lastErr = fmt.Errorf("error 529: service overloaded, retrying in %v", delay)
				if err := sleepWithContext(ctx, delay); err != nil {
					return nil, err
				}
				continue
			}
			return nil, &APIError{StatusCode: 529, RawBody: "service overloaded after retries"}

		default:
			return nil, &APIError{StatusCode: resp.StatusCode, RawBody: string(body)}
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("unknown error after retries")
}

// parseAPIError parses a JSON error response body into a structured APIError.
func (c *Client) parseAPIError(statusCode int, body []byte) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		RawBody:    string(body),
	}

	var parsed models.APIError
	if err := json.Unmarshal(body, &parsed); err == nil && len(parsed.Errors) > 0 {
		apiErr.Errors = parsed.Errors
	}

	return apiErr
}

// Info retrieves information about the SSL Labs service and current capacity.
// It calls the /info endpoint which does not require authentication.
func (c *Client) Info(ctx context.Context) (*models.Info, error) {
	body, err := c.doRequest(ctx, "info", nil)
	if err != nil {
		return nil, err
	}

	var info models.Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	return &info, nil
}

// Analyze initiates or retrieves an analysis for the specified host.
// Set startNew to true to start a fresh analysis, false to check existing.
func (c *Client) Analyze(ctx context.Context, host string, startNew bool) (*models.Host, error) {
	params := url.Values{}
	params.Set("host", host)
	params.Set("all", "done") // Get complete details when ready

	if startNew {
		params.Set("startNew", "on")
	}

	body, err := c.doRequest(ctx, "analyze", params)
	if err != nil {
		return nil, err
	}

	var result models.Host
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	return &result, nil
}

// AnalyzeWithPolling performs a complete analysis with automatic polling.
// It respects the context for cancellation and returns partial results on error.
// The onProgress callback is called with status updates during polling.
func (c *Client) AnalyzeWithPolling(ctx context.Context, host string, coolOff time.Duration, onProgress func(status, msg string)) (*models.Host, error) {
	// Respect cool-off period before starting new analysis
	if coolOff > 0 {
		if err := sleepWithContext(ctx, coolOff); err != nil {
			return nil, fmt.Errorf("cancelled during cool-off: %w", err)
		}
	}

	// Start new analysis
	result, err := c.Analyze(ctx, host, true)
	if err != nil {
		return nil, fmt.Errorf("error starting analysis: %w", err)
	}

	// Poll until analysis is complete
	for result.Status != models.StatusReady && result.Status != models.StatusError {
		if onProgress != nil {
			onProgress(result.Status, result.StatusMessage)
		}

		// Use variable interval as recommended by documentation
		pollInterval := InitialPollInterval
		if result.Status == models.StatusInProgress {
			pollInterval = ActivePollInterval
		}

		// Respect context during sleep
		if err := sleepWithContext(ctx, pollInterval); err != nil {
			// Return partial result on cancellation
			return result, fmt.Errorf("analysis cancelled: %w", err)
		}

		// Query status (without startNew to avoid restarting)
		newResult, err := c.Analyze(ctx, host, false)
		if err != nil {
			// Return last known result along with the error
			return result, fmt.Errorf("error querying status: %w", err)
		}
		result = newResult
	}

	if result.Status == models.StatusError {
		return result, fmt.Errorf("analysis completed with error: %s", result.StatusMessage)
	}

	return result, nil
}
