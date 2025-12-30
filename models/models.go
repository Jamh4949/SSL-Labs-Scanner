// Package models contiene las estructuras de datos para la API de SSL Labs v4
package models

// Info representa la respuesta del endpoint /info
type Info struct {
	EngineVersion        string   `json:"engineVersion"`
	CriteriaVersion      string   `json:"criteriaVersion"`
	MaxAssessments       int      `json:"maxAssessments"`
	CurrentAssessments   int      `json:"currentAssessments"`
	NewAssessmentCoolOff int64    `json:"newAssessmentCoolOff"`
	Messages             []string `json:"messages"`
}

// Host representa la respuesta principal del análisis
type Host struct {
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Protocol        string     `json:"protocol"`
	IsPublic        bool       `json:"isPublic"`
	Status          string     `json:"status"`
	StatusMessage   string     `json:"statusMessage"`
	StartTime       int64      `json:"startTime"`
	TestTime        int64      `json:"testTime"`
	EngineVersion   string     `json:"engineVersion"`
	CriteriaVersion string     `json:"criteriaVersion"`
	Endpoints       []Endpoint `json:"endpoints"`
}

// Endpoint representa un servidor/IP analizado
type Endpoint struct {
	IPAddress            string           `json:"ipAddress"`
	ServerName           string           `json:"serverName"`
	StatusMessage        string           `json:"statusMessage"`
	StatusDetails        string           `json:"statusDetails"`
	StatusDetailsMessage string           `json:"statusDetailsMessage"`
	Grade                string           `json:"grade"`
	GradeTrustIgnored    string           `json:"gradeTrustIgnored"`
	FutureGrade          string           `json:"futureGrade"`
	HasWarnings          bool             `json:"hasWarnings"`
	IsExceptional        bool             `json:"isExceptional"`
	Progress             int              `json:"progress"`
	ETA                  int              `json:"eta"`
	Delegation           int              `json:"delegation"`
	Details              *EndpointDetails `json:"details,omitempty"`
}

// EndpointDetails contiene información detallada de vulnerabilidades
type EndpointDetails struct {
	HostStartTime int64 `json:"hostStartTime"`

	// Vulnerabilidades críticas
	VulnBeast       bool `json:"vulnBeast"`
	Heartbleed      bool `json:"heartbleed"`
	Poodle          bool `json:"poodle"`
	PoodleTLS       int  `json:"poodleTls"`
	Freak           bool `json:"freak"`
	Logjam          bool `json:"logjam"`
	DrownVulnerable bool `json:"drownVulnerable"`

	// Otras vulnerabilidades con valores numéricos
	OpenSslCcs              int `json:"openSslCcs"`
	OpenSSLLuckyMinus20     int `json:"openSSLLuckyMinus20"`
	Ticketbleed             int `json:"ticketbleed"`
	Bleichenbacher          int `json:"bleichenbacher"`
	ZombiePoodle            int `json:"zombiePoodle"`
	GoldenDoodle            int `json:"goldenDoodle"`
	ZeroLengthPaddingOracle int `json:"zeroLengthPaddingOracle"`
	SleepingPoodle          int `json:"sleepingPoodle"`

	// Soporte de protocolos
	SupportsRc4  bool `json:"supportsRc4"`
	SupportsAead bool `json:"supportsAead"`
	SupportsCBC  bool `json:"supportsCBC"`
}

// ErrorDetail representa un detalle de error individual
type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// APIError representa un error de la API
type APIError struct {
	Errors []ErrorDetail `json:"errors"`
}

// Constantes de estado del análisis
const (
	StatusDNS        = "DNS"
	StatusError      = "ERROR"
	StatusInProgress = "IN_PROGRESS"
	StatusReady      = "READY"
)
