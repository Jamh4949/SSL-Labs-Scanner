// Package client proporciona el cliente HTTP para la API de SSL Labs v4
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

const (
	// BaseURL es la URL base de la API de SSL Labs v4
	BaseURL = "https://api.ssllabs.com/api/v4"

	// Version de la herramienta para User-Agent
	Version = "1.0.0"

	// Intervalos de polling recomendados por la documentación
	InitialPollInterval = 5 * time.Second  // Antes de IN_PROGRESS
	ActivePollInterval  = 10 * time.Second // Durante IN_PROGRESS

	// Reintentos para errores temporales
	MaxRetries          = 3
	MaxNetRetries       = 2               // Reintentos para errores de red transitorios
	RetryJitterFraction = 0.2             // ±20% de variación aleatoria
	NetRetryDelay       = 5 * time.Second // Delay base para errores de red

	// Delays para reintentos HTTP (reducidos para demo; en producción usar 15min/30min según docs)
	RetryDelay503 = 30 * time.Second // Producción: 15 * time.Minute
	RetryDelay529 = 45 * time.Second // Producción: 30 * time.Minute

	// Límite de tamaño de respuesta para evitar ataques de memoria
	MaxBodySize = 10 * 1024 * 1024 // 10 MB
)

// RateLimitInfo contiene información de límites de la API
type RateLimitInfo struct {
	MaxAssessments     int
	CurrentAssessments int
}

// Client es el cliente para la API de SSL Labs
type Client struct {
	httpClient *http.Client
	email      string
	baseURL    string
	userAgent  string
	rng        *rand.Rand // Generador de números aleatorios con semilla propia

	// Protección para acceso concurrente a lastRateLimit
	rlMu          sync.RWMutex
	lastRateLimit RateLimitInfo
}

// New crea un nuevo cliente de SSL Labs
func New(email string) *Client {
	// Crear generador de números aleatorios con semilla única
	// (evita el problema de math/rand global sin semilla en Go < 1.20)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Configurar Transport con soporte para proxy y conexiones reutilizables
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false,
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: transport,
		},
		email:     email,
		baseURL:   BaseURL,
		userAgent: fmt.Sprintf("SSLLabsScanner/%s (Go)", Version),
		rng:       rng,
	}
}

// GetRateLimitInfo devuelve la última información de rate limiting (thread-safe)
func (c *Client) GetRateLimitInfo() RateLimitInfo {
	c.rlMu.RLock()
	defer c.rlMu.RUnlock()
	return c.lastRateLimit
}

// updateRateLimit actualiza la información de rate limiting (thread-safe)
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

// ValidateEmail valida si el email es aceptable (no Gmail/Yahoo/Hotmail)
// Nota: es heurístico; SSL Labs puede cambiar dominios bloqueados
func ValidateEmail(email string) (warnings []string) {
	lower := strings.ToLower(email)
	blockedDomains := []string{"@gmail.", "@yahoo.", "@hotmail.", "@outlook.com", "@live.com"}

	for _, domain := range blockedDomains {
		if strings.Contains(lower, domain) {
			warnings = append(warnings, fmt.Sprintf(
				"⚠️  Advertencia: SSL Labs no permite emails de servicios gratuitos (%s). El registro puede fallar.",
				domain))
			break
		}
	}

	if !strings.Contains(email, "@") {
		warnings = append(warnings, "⚠️  Advertencia: El email no parece válido (falta @)")
	}

	return warnings
}

// APIError representa un error estructurado de la API
type APIError struct {
	StatusCode int
	RawBody    string
	Errors     []models.ErrorDetail
}

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

// sleepWithContext duerme respetando el contexto
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// addJitter añade variación aleatoria al delay (±20%)
func (c *Client) addJitter(d time.Duration) time.Duration {
	jitter := float64(d) * RetryJitterFraction
	offset := (c.rng.Float64() * 2 * jitter) - jitter
	return d + time.Duration(offset)
}

// parseRetryAfter parsea el header Retry-After (segundos o HTTP-date)
func (c *Client) parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}

	// Intentar parsear como segundos
	if secs, err := strconv.Atoi(value); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}

	// Intentar parsear como HTTP-date
	if t, err := http.ParseTime(value); err == nil {
		delay := time.Until(t)
		if delay > 0 {
			return delay
		}
	}

	return 0
}

// isTemporaryNetError determina si un error de red es transitorio y vale la pena reintentar
func isTemporaryNetError(err error) bool {
	if err == nil {
		return false
	}

	// Verificar si es un error de red con método Temporary()
	var netErr net.Error
	if ok := errors.As(err, &netErr); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	// Verificar errores comunes transitorios por mensaje
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

// doRequest ejecuta una petición HTTP con headers, reintentos y rate limiting
func (c *Client) doRequest(ctx context.Context, endpoint string, params url.Values) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s", c.baseURL, endpoint)
	if len(params) > 0 {
		reqURL = fmt.Sprintf("%s?%s", reqURL, params.Encode())
	}

	var lastErr error
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creando request: %w", err)
		}

		// Headers requeridos y recomendados
		req.Header.Set("email", c.email)
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "application/json")

		// Ejecutar request con reintentos para errores de red transitorios
		var resp *http.Response
		var body []byte

		for netAttempt := 0; netAttempt <= MaxNetRetries; netAttempt++ {
			resp, err = c.httpClient.Do(req)
			if err == nil {
				break
			}

			// Si es error transitorio y quedan reintentos, esperar y reintentar
			if isTemporaryNetError(err) && netAttempt < MaxNetRetries {
				delay := c.addJitter(NetRetryDelay)
				lastErr = fmt.Errorf("error de red transitorio (intento %d/%d): %w", netAttempt+1, MaxNetRetries+1, err)
				if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
					return nil, sleepErr
				}
				// Recrear request ya que el anterior puede estar "usado"
				req, _ = http.NewRequestWithContext(ctx, "GET", reqURL, nil)
				req.Header.Set("email", c.email)
				req.Header.Set("User-Agent", c.userAgent)
				req.Header.Set("Accept", "application/json")
				continue
			}

			return nil, fmt.Errorf("error en la petición: %w", err)
		}

		if resp == nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("error desconocido: respuesta nula")
		}

		// Limitar lectura del body para evitar ataques de memoria
		limitedReader := io.LimitReader(resp.Body, MaxBodySize+1)
		body, err = io.ReadAll(limitedReader)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("error leyendo respuesta: %w", err)
		}
		if len(body) > MaxBodySize {
			return nil, fmt.Errorf("respuesta demasiado grande (>%d bytes)", MaxBodySize)
		}

		// Leer headers de rate limiting (thread-safe)
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

		// Manejo de códigos según documentación
		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil

		case http.StatusBadRequest:
			return nil, c.parseAPIError(400, body)

		case 429:
			// 429: verificar Retry-After antes de fallar
			if attempt < MaxRetries {
				if delay := c.parseRetryAfter(resp.Header.Get("Retry-After")); delay > 0 {
					lastErr = fmt.Errorf("error 429: demasiadas peticiones, esperando %v", delay)
					if err := sleepWithContext(ctx, c.addJitter(delay)); err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, &APIError{
				StatusCode: 429,
				RawBody:    "demasiadas peticiones - reduzca la concurrencia y espere",
			}

		case 441:
			return nil, &APIError{
				StatusCode: 441,
				RawBody:    "no autorizado - debe registrarse primero en la API",
			}

		case http.StatusInternalServerError:
			// 500: error severo, no reintentar en bucle
			return nil, &APIError{StatusCode: 500, RawBody: string(body)}

		case http.StatusServiceUnavailable:
			// 503: servicio no disponible, reintentar con delay largo
			if attempt < MaxRetries {
				delay := c.addJitter(RetryDelay503)
				lastErr = fmt.Errorf("error 503: servicio no disponible, reintentando en %v", delay)
				if err := sleepWithContext(ctx, delay); err != nil {
					return nil, err
				}
				continue
			}
			return nil, &APIError{StatusCode: 503, RawBody: "servicio no disponible tras reintentos"}

		case 529:
			// 529: sobrecargado, reintentar con delay más largo
			if attempt < MaxRetries {
				delay := c.addJitter(RetryDelay529)
				lastErr = fmt.Errorf("error 529: servicio sobrecargado, reintentando en %v", delay)
				if err := sleepWithContext(ctx, delay); err != nil {
					return nil, err
				}
				continue
			}
			return nil, &APIError{StatusCode: 529, RawBody: "servicio sobrecargado tras reintentos"}

		default:
			return nil, &APIError{StatusCode: resp.StatusCode, RawBody: string(body)}
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("error desconocido tras reintentos")
}

// parseAPIError parsea el cuerpo de error JSON a estructura
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

// Info obtiene información del servidor SSL Labs
func (c *Client) Info(ctx context.Context) (*models.Info, error) {
	body, err := c.doRequest(ctx, "info", nil)
	if err != nil {
		return nil, err
	}

	var info models.Info
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("error parseando JSON: %w", err)
	}

	return &info, nil
}

// Analyze inicia o consulta un análisis
func (c *Client) Analyze(ctx context.Context, host string, startNew bool) (*models.Host, error) {
	params := url.Values{}
	params.Set("host", host)
	params.Set("all", "done") // Obtener detalles completos cuando esté listo

	if startNew {
		params.Set("startNew", "on")
	}

	body, err := c.doRequest(ctx, "analyze", params)
	if err != nil {
		return nil, err
	}

	var result models.Host
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parseando JSON: %w", err)
	}

	return &result, nil
}

// AnalyzeWithPolling realiza un análisis completo con polling automático
// Respeta context para cancelación y devuelve resultados parciales en caso de error
func (c *Client) AnalyzeWithPolling(ctx context.Context, host string, coolOff time.Duration, onProgress func(status, msg string)) (*models.Host, error) {
	// Respetar cool-off antes de iniciar nuevo análisis
	if coolOff > 0 {
		if err := sleepWithContext(ctx, coolOff); err != nil {
			return nil, fmt.Errorf("cancelado durante cool-off: %w", err)
		}
	}

	// Iniciar nuevo análisis
	result, err := c.Analyze(ctx, host, true)
	if err != nil {
		return nil, fmt.Errorf("error iniciando análisis: %w", err)
	}

	// Polling hasta que el análisis esté completo
	for result.Status != models.StatusReady && result.Status != models.StatusError {
		if onProgress != nil {
			onProgress(result.Status, result.StatusMessage)
		}

		// Usar intervalo variable según documentación
		pollInterval := InitialPollInterval
		if result.Status == models.StatusInProgress {
			pollInterval = ActivePollInterval
		}

		// Respetar contexto durante el sleep
		if err := sleepWithContext(ctx, pollInterval); err != nil {
			// Devolver resultado parcial en caso de cancelación
			return result, fmt.Errorf("análisis cancelado: %w", err)
		}

		// Consultar estado (sin startNew para no reiniciar)
		newResult, err := c.Analyze(ctx, host, false)
		if err != nil {
			// Devolver último resultado conocido junto con el error
			return result, fmt.Errorf("error consultando estado: %w", err)
		}
		result = newResult
	}

	if result.Status == models.StatusError {
		return result, fmt.Errorf("análisis terminó con error: %s", result.StatusMessage)
	}

	return result, nil
}
