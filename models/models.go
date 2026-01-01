// Package models provides data structures for the SSL Labs API v4 responses.
// These structs are designed to unmarshal JSON responses from the API endpoints.
// Reference: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md
package models

// Info represents the response from the /info endpoint.
// It provides information about the SSL Labs engine and current assessment capacity.
type Info struct {
	EngineVersion        string   `json:"engineVersion"`        // SSL Labs engine version (e.g., "2.4.1")
	CriteriaVersion      string   `json:"criteriaVersion"`      // Grading criteria version (e.g., "2009q")
	MaxAssessments       int      `json:"maxAssessments"`       // Maximum concurrent assessments allowed
	CurrentAssessments   int      `json:"currentAssessments"`   // Number of assessments currently in progress
	NewAssessmentCoolOff int64    `json:"newAssessmentCoolOff"` // Cooldown in milliseconds before starting new assessment
	Messages             []string `json:"messages"`             // Service announcements or warnings
}

// Host represents the main analysis response from the /analyze endpoint.
// It contains the overall analysis status and results for all endpoints (IPs).
type Host struct {
	Host            string     `json:"host"`            // Hostname being analyzed
	Port            int        `json:"port"`            // Port number (typically 443)
	Protocol        string     `json:"protocol"`        // Protocol (typically "http")
	IsPublic        bool       `json:"isPublic"`        // Whether the assessment is publicly visible
	Status          string     `json:"status"`          // Current status: DNS, IN_PROGRESS, READY, or ERROR
	StatusMessage   string     `json:"statusMessage"`   // Human-readable status description
	StartTime       int64      `json:"startTime"`       // Unix timestamp when assessment started
	TestTime        int64      `json:"testTime"`        // Unix timestamp when assessment completed
	EngineVersion   string     `json:"engineVersion"`   // Engine version used for this assessment
	CriteriaVersion string     `json:"criteriaVersion"` // Criteria version used for grading
	Endpoints       []Endpoint `json:"endpoints"`       // List of server endpoints (IPs) analyzed
}

// Endpoint represents a single server/IP that was analyzed.
// A host may have multiple endpoints if it resolves to multiple IP addresses (IPv4/IPv6).
type Endpoint struct {
	IPAddress            string           `json:"ipAddress"`            // Server IP address (IPv4 or IPv6)
	ServerName           string           `json:"serverName"`           // Server name from certificate or reverse DNS
	StatusMessage        string           `json:"statusMessage"`        // Endpoint-specific status message
	StatusDetails        string           `json:"statusDetails"`        // Detailed status information
	StatusDetailsMessage string           `json:"statusDetailsMessage"` // Human-readable status details
	Grade                string           `json:"grade"`                // SSL grade: A+, A, A-, B, C, D, E, F, T, or M
	GradeTrustIgnored    string           `json:"gradeTrustIgnored"`    // Grade if trust issues are ignored
	FutureGrade          string           `json:"futureGrade"`          // Predicted grade based on upcoming criteria
	HasWarnings          bool             `json:"hasWarnings"`          // Whether there are non-critical warnings
	IsExceptional        bool             `json:"isExceptional"`        // Whether configuration is exceptionally good
	Progress             int              `json:"progress"`             // Analysis progress percentage (0-100)
	ETA                  int              `json:"eta"`                  // Estimated time to completion in seconds
	Delegation           int              `json:"delegation"`           // Delegation status
	Details              *EndpointDetails `json:"details,omitempty"`    // Detailed vulnerability info (nil if not ready)
}

// EndpointDetails contains detailed vulnerability and protocol support information.
// These fields map to specific CVEs and security checks performed by SSL Labs.
type EndpointDetails struct {
	HostStartTime int64 `json:"hostStartTime"` // When this endpoint's analysis started

	// Critical vulnerabilities - boolean flags (true = vulnerable)
	VulnBeast       bool `json:"vulnBeast"`       // BEAST attack (CVE-2011-3389) - Note: mitigated in modern browsers
	Heartbleed      bool `json:"heartbleed"`      // Heartbleed (CVE-2014-0160) - Critical memory disclosure
	Poodle          bool `json:"poodle"`          // POODLE SSL 3.0 (CVE-2014-3566)
	PoodleTLS       int  `json:"poodleTls"`       // POODLE TLS variant (-3=timeout, -2=error, -1=unknown, 0=not vuln, 1=maybe, 2=vuln)
	Freak           bool `json:"freak"`           // FREAK attack (CVE-2015-0204) - Export cipher downgrade
	Logjam          bool `json:"logjam"`          // Logjam (CVE-2015-4000) - Weak DH parameters
	DrownVulnerable bool `json:"drownVulnerable"` // DROWN (CVE-2016-0800) - Cross-protocol attack using SSLv2

	// Numeric vulnerability indicators (0-1 = safe, 2+ = vulnerable in most cases)
	OpenSslCcs              int `json:"openSslCcs"`              // CCS Injection (CVE-2014-0224): 0=unknown, 1=safe, 2=maybe, 3=vulnerable
	OpenSSLLuckyMinus20     int `json:"openSSLLuckyMinus20"`     // Lucky Minus 20 (CVE-2016-2107): 0=unknown, 1=safe, 2=vulnerable
	Ticketbleed             int `json:"ticketbleed"`             // Ticketbleed (CVE-2016-9244): 0=unknown, 1=safe, 2=vulnerable
	Bleichenbacher          int `json:"bleichenbacher"`          // ROBOT attack: 0=unknown, 1=safe, 2-5=varying vuln levels
	ZombiePoodle            int `json:"zombiePoodle"`            // Zombie POODLE: 0=unknown, 1=safe, 2-10=vulnerable variants
	GoldenDoodle            int `json:"goldenDoodle"`            // GOLDENDOODLE: 0=unknown, 1=safe, 4+=vulnerable
	ZeroLengthPaddingOracle int `json:"zeroLengthPaddingOracle"` // 0-Length Padding Oracle
	SleepingPoodle          int `json:"sleepingPoodle"`          // Sleeping POODLE: 0=unknown, 1=safe, 10+=vulnerable

	// Protocol and cipher support flags
	SupportsRc4  bool `json:"supportsRc4"`  // Whether RC4 ciphers are supported (deprecated)
	SupportsAead bool `json:"supportsAead"` // Whether AEAD ciphers are supported (recommended)
	SupportsCBC  bool `json:"supportsCBC"`  // Whether CBC mode ciphers are supported
}

// ErrorDetail represents a single error field from the API error response.
type ErrorDetail struct {
	Field   string `json:"field"`   // The field that caused the error (if applicable)
	Message string `json:"message"` // Human-readable error message
}

// APIError represents a structured error response from the SSL Labs API.
// The API returns errors in this format for 4xx responses.
type APIError struct {
	Errors []ErrorDetail `json:"errors"` // List of error details
}

// Analysis status constants as returned by the API.
const (
	StatusDNS        = "DNS"         // Resolving domain names
	StatusError      = "ERROR"       // Analysis failed with an error
	StatusInProgress = "IN_PROGRESS" // Analysis is running
	StatusReady      = "READY"       // Analysis completed successfully
)
