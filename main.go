/*
SSL Labs Scanner - Challenge Técnico

Este programa analiza la seguridad TLS de un dominio usando la API pública
de SSL Labs v4.

Uso:

	go run main.go -email tu@empresa.com -host dominio.com

Requisitos:
  - Email registrado previamente en SSL Labs (ver README.md)
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ssllabs-scanner/client"
	"ssllabs-scanner/models"
)

// ============================================================================
// ANSI Colors & Styles - Sin dependencias externas
// ============================================================================

// colorEnabled controla si se usan colores ANSI
var colorEnabled = true

// Códigos ANSI
const (
	ansiReset = "\033[0m"

	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiItalic    = "\033[3m"
	ansiUnderline = "\033[4m"

	ansiBlack   = "\033[30m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
	ansiWhite   = "\033[37m"
	ansiGray    = "\033[90m"

	ansiBrightRed    = "\033[91m"
	ansiBrightGreen  = "\033[92m"
	ansiBrightYellow = "\033[93m"
	ansiBrightBlue   = "\033[94m"
	ansiBrightCyan   = "\033[96m"
)

// Símbolos Unicode (estos no dependen de colorEnabled)
const (
	symbolCheck   = "✓"
	symbolCross   = "✗"
	symbolWarning = "⚠"
	symbolStar    = "★"
	symbolArrow   = "→"
	symbolDot     = "●"
	symbolCircle  = "○"
	symbolBox     = "■"
	symbolLine    = "─"
)

// Funciones que devuelven códigos solo si colorEnabled
func reset() string {
	if colorEnabled {
		return ansiReset
	}
	return ""
}
func bold() string {
	if colorEnabled {
		return ansiBold
	}
	return ""
}
func dim() string {
	if colorEnabled {
		return ansiDim
	}
	return ""
}
func underline() string {
	if colorEnabled {
		return ansiUnderline
	}
	return ""
}
func red() string {
	if colorEnabled {
		return ansiRed
	}
	return ""
}
func green() string {
	if colorEnabled {
		return ansiGreen
	}
	return ""
}
func yellow() string {
	if colorEnabled {
		return ansiYellow
	}
	return ""
}
func cyan() string {
	if colorEnabled {
		return ansiCyan
	}
	return ""
}
func gray() string {
	if colorEnabled {
		return ansiGray
	}
	return ""
}
func white() string {
	if colorEnabled {
		return ansiWhite
	}
	return ""
}
func brightRed() string {
	if colorEnabled {
		return ansiBrightRed
	}
	return ""
}
func brightGreen() string {
	if colorEnabled {
		return ansiBrightGreen
	}
	return ""
}
func brightCyan() string {
	if colorEnabled {
		return ansiBrightCyan
	}
	return ""
}

// style aplica estilos ANSI a un texto
func style(text string, styles ...string) string {
	if !colorEnabled || len(styles) == 0 {
		return text
	}
	prefix := strings.Join(styles, "")
	return prefix + text + ansiReset
}

// Helpers para estilos comunes
func success(text string) string  { return style(text, green()) }
func successB(text string) string { return style(text, bold(), green()) }
func warning(text string) string  { return style(text, yellow()) }
func warningB(text string) string { return style(text, bold(), yellow()) }
func danger(text string) string   { return style(text, red()) }
func dangerB(text string) string  { return style(text, bold(), red()) }
func info(text string) string     { return style(text, cyan()) }
func infoB(text string) string    { return style(text, bold(), cyan()) }
func muted(text string) string    { return style(text, gray()) }
func header(text string) string   { return style(text, bold(), brightCyan()) }
func label(text string) string    { return style(text, dim()) }

// line genera una línea decorativa
func line(length int) string {
	return muted(strings.Repeat(symbolLine, length))
}

// ============================================================================
// Main
// ============================================================================

func main() {
	// Parsear argumentos de línea de comandos
	emailFlag := flag.String("email", "", "Email registrado en SSL Labs (o usar SSLLABS_EMAIL env var)")
	host := flag.String("host", "", "Dominio a analizar (obligatorio)")
	timeout := flag.Duration("timeout", 10*time.Minute, "Timeout máximo para el análisis")
	noColor := flag.Bool("no-color", false, "Desactivar colores en la salida")
	flag.Parse()

	// Desactivar colores si se solicita o si no es terminal
	if *noColor || os.Getenv("NO_COLOR") != "" {
		disableColors()
	}

	// Email: prioridad flag > variable de entorno
	email := *emailFlag
	if email == "" {
		email = os.Getenv("SSLLABS_EMAIL")
	}

	// Validar argumentos
	if email == "" || *host == "" {
		fmt.Println(dangerB("Error: ") + "Se requieren los parámetros " + info("-email") + " (o " + info("SSLLABS_EMAIL") + ") y " + info("-host"))
		fmt.Println()
		flag.Usage()
		os.Exit(1)
	}

	// Validar email (advertencia si usa dominio gratuito)
	if warnings := client.ValidateEmail(email); len(warnings) > 0 {
		for _, w := range warnings {
			fmt.Println(warningB(symbolWarning+" ") + w)
		}
		fmt.Println()
	}

	// Crear contexto con cancelación (Ctrl+C) y timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Manejar señales de interrupción
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		fmt.Println(warningB(symbolWarning + " Cancelando análisis..."))
		cancel()
	}()

	// Crear cliente
	c := client.New(email)

	// Banner
	printBanner()

	// Verificar disponibilidad de la API
	fmt.Println(info(symbolArrow) + " Verificando disponibilidad de SSL Labs...")

	apiInfo, err := c.Info(ctx)
	if err != nil {
		fmt.Println(dangerB(symbolCross+" Error: ") + fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	fmt.Println(successB(symbolCheck) + " SSL Labs " + success("disponible"))
	fmt.Println(muted("  Engine: "+apiInfo.EngineVersion) + muted(" │ Criteria: "+apiInfo.CriteriaVersion))
	fmt.Println(muted(fmt.Sprintf("  Assessments: %d/%d", apiInfo.CurrentAssessments, apiInfo.MaxAssessments)))

	// Mostrar cool-off si existe
	coolOff := time.Duration(apiInfo.NewAssessmentCoolOff) * time.Millisecond
	if coolOff > 0 {
		fmt.Println(muted(fmt.Sprintf("  Cool-off: %v", coolOff)))
	}
	fmt.Println()

	// Iniciar análisis con polling
	fmt.Println(header(symbolDot+" Analizando: ") + infoB(*host))
	fmt.Println(muted("  (Esto puede tomar varios minutos... Ctrl+C para cancelar)"))
	fmt.Println()

	result, err := c.AnalyzeWithPolling(ctx, *host, coolOff, func(status, msg string) {
		statusColor := getStatusColor(status)
		fmt.Printf("  %s %s\n", style("["+status+"]", statusColor), muted(msg))
	})

	// Mostrar información de rate limiting actualizada
	rateLimit := c.GetRateLimitInfo()
	if rateLimit.MaxAssessments > 0 {
		fmt.Println()
		fmt.Println(muted(fmt.Sprintf("  Rate limit: %d/%d assessments",
			rateLimit.CurrentAssessments, rateLimit.MaxAssessments)))
	}

	if err != nil {
		fmt.Println()
		fmt.Println(dangerB(symbolCross+" Error: ") + fmt.Sprintf("%v", err))
		// Si hay resultados parciales, mostrarlos
		if result != nil && len(result.Endpoints) > 0 {
			fmt.Println()
			fmt.Println(warningB("═══ RESULTADOS PARCIALES ═══"))
			printResults(result)
		}
		os.Exit(1)
	}

	// Mostrar resultados
	fmt.Println()
	printResults(result)
}

// ============================================================================
// Output Functions
// ============================================================================

// printBanner imprime el banner del programa
func printBanner() {
	fmt.Println()
	fmt.Println(header("╔══════════════════════════════════════╗"))
	fmt.Println(header("║") + "      " + style("SSL Labs Scanner", bold(), brightCyan()) + "  " + muted("v1.0") + "      " + header("║"))
	fmt.Println(header("║") + "   " + muted("TLS Security Analysis Tool") + "      " + header("║"))
	fmt.Println(header("╚══════════════════════════════════════╝"))
	fmt.Println()
}

// getStatusColor devuelve el color apropiado para un status
func getStatusColor(status string) string {
	switch status {
	case "READY":
		return green()
	case "ERROR":
		return red()
	case "IN_PROGRESS":
		return yellow()
	case "DNS":
		return cyan()
	default:
		return gray()
	}
}

// printResults muestra los resultados del análisis
func printResults(result *models.Host) {
	fmt.Println(header("╔══════════════════════════════════════╗"))
	fmt.Println(header("║") + "           " + style("RESULTADOS", bold(), white()) + "              " + header("║"))
	fmt.Println(header("╚══════════════════════════════════════╝"))
	fmt.Println()

	// Información del host
	fmt.Println(label("  Dominio: ") + infoB(result.Host))
	if result.Port > 0 {
		fmt.Println(label("  Puerto:  ") + info(fmt.Sprintf("%d", result.Port)))
	}
	fmt.Println()

	if len(result.Endpoints) == 0 {
		fmt.Println(warning("  No se encontraron endpoints para analizar."))
		return
	}

	for i, endpoint := range result.Endpoints {
		printEndpoint(i+1, endpoint)
	}
}

// printEndpoint imprime información de un endpoint
func printEndpoint(num int, endpoint models.Endpoint) {
	fmt.Println(line(42))
	fmt.Println(style(fmt.Sprintf("  %s Endpoint %d", symbolBox, num), bold()))
	fmt.Println(line(42))
	fmt.Println()

	// IP y servidor
	fmt.Println(label("  IP:     ") + info(endpoint.IPAddress))
	if endpoint.ServerName != "" {
		fmt.Println(label("  Server: ") + muted(endpoint.ServerName))
	}
	fmt.Println()

	// Grade - la parte más importante
	printGrade(endpoint.Grade)

	if endpoint.GradeTrustIgnored != "" && endpoint.GradeTrustIgnored != endpoint.Grade {
		fmt.Println(label("  Grade (ignorando trust): ") + formatGradeCompact(endpoint.GradeTrustIgnored))
	}

	if endpoint.FutureGrade != "" {
		fmt.Println(label("  Future Grade: ") + formatGradeCompact(endpoint.FutureGrade))
	}

	// Warnings y excepciones
	if endpoint.HasWarnings {
		fmt.Println()
		fmt.Println(warningB("  "+symbolWarning+" Advertencias") + warning(" que pueden afectar el score"))
	}

	if endpoint.IsExceptional {
		fmt.Println()
		fmt.Println(style("  "+symbolStar+" Configuración excepcional", bold(), brightGreen()))
	}

	// Vulnerabilidades
	if endpoint.Details != nil {
		fmt.Println()
		printVulnerabilities(endpoint.Details)
	}

	fmt.Println()
}

// printGrade imprime el grade con formato visual destacado
func printGrade(grade string) {
	if grade == "" {
		fmt.Println(label("  Grade:  ") + muted("(pendiente)"))
		return
	}

	var gradeStyle, symbol, status string

	switch {
	case grade == "A+":
		gradeStyle = style(grade, bold(), brightGreen())
		symbol = style(symbolStar, brightGreen())
		status = success("Excelente")
	case grade == "A":
		gradeStyle = style(grade, bold(), green())
		symbol = style(symbolCheck, green())
		status = success("Muy bueno")
	case grade == "A-":
		gradeStyle = style(grade, bold(), green())
		symbol = style(symbolCheck, green())
		status = success("Bueno")
	case grade == "B":
		gradeStyle = style(grade, bold(), yellow())
		symbol = style(symbolCircle, yellow())
		status = warning("Aceptable")
	case grade == "C":
		gradeStyle = style(grade, bold(), yellow())
		symbol = style(symbolWarning, yellow())
		status = warning("Mejorable")
	case grade == "D" || grade == "E":
		gradeStyle = style(grade, bold(), red())
		symbol = style(symbolWarning, red())
		status = danger("Inseguro")
	case grade == "F":
		gradeStyle = style(grade, bold(), brightRed())
		symbol = style(symbolCross, brightRed())
		status = dangerB("Crítico")
	case grade == "T":
		gradeStyle = style(grade, bold(), red())
		symbol = style(symbolCross, red())
		status = danger("Sin confianza")
	case grade == "M":
		gradeStyle = style(grade, bold(), red())
		symbol = style(symbolWarning, red())
		status = danger("Mismatch certificado")
	default:
		gradeStyle = style(grade, bold())
		symbol = "?"
		status = muted("Desconocido")
	}

	fmt.Println()
	fmt.Println(style("  ┌─────────────────────────────┐", dim()))
	fmt.Printf("  │   Grade: %s  %s         │\n", gradeStyle, symbol)
	fmt.Printf("  │   %s                  │\n", status)
	fmt.Println(style("  └─────────────────────────────┘", dim()))
	fmt.Println()
}

// formatGradeCompact devuelve el grade con color pero sin caja
func formatGradeCompact(grade string) string {
	switch {
	case strings.HasPrefix(grade, "A"):
		return style(grade+" "+symbolCheck, green())
	case grade == "B":
		return style(grade+" "+symbolCircle, yellow())
	case grade == "C":
		return style(grade+" "+symbolWarning, yellow())
	case grade == "D" || grade == "E" || grade == "F":
		return style(grade+" "+symbolCross, red())
	case grade == "T" || grade == "M":
		return style(grade+" "+symbolCross, red())
	default:
		return grade
	}
}

// printVulnerabilities muestra el resumen de vulnerabilidades
// Separamos en CRÍTICAS (exploits activos) vs INFORMATIVAS (históricas/mitigadas)
func printVulnerabilities(details *models.EndpointDetails) {
	// ═══════════════════════════════════════════════════════════════════════
	// VULNERABILIDADES CRÍTICAS - Exploits reales que requieren acción
	// ═══════════════════════════════════════════════════════════════════════
	fmt.Println(style("  Vulnerabilidades Críticas", bold(), underline()))
	fmt.Println()

	criticalVulns := []struct {
		name       string
		vulnerable bool
	}{
		{"Heartbleed", details.Heartbleed}, // CVE-2014-0160 - Memory disclosure
		{"DROWN", details.DrownVulnerable}, // CVE-2016-0800 - Cross-protocol attack
	}

	criticalNumeric := []struct {
		name      string
		value     int
		threshold int
	}{
		{"ROBOT", details.Bleichenbacher, 2},               // Return Of Bleichenbacher Oracle
		{"OpenSSL CCS", details.OpenSslCcs, 2},             // CVE-2014-0224
		{"Lucky Minus 20", details.OpenSSLLuckyMinus20, 2}, // CVE-2016-2107
		{"Ticketbleed", details.Ticketbleed, 2},            // CVE-2016-9244
	}

	hasCritical := false

	for _, v := range criticalVulns {
		if v.vulnerable {
			fmt.Printf("  %s %-16s %s\n", dangerB(symbolCross), v.name, dangerB("VULNERABLE"))
			hasCritical = true
		} else {
			fmt.Printf("  %s %-16s %s\n", success(symbolCheck), v.name, muted("Seguro"))
		}
	}

	for _, v := range criticalNumeric {
		if v.value >= v.threshold {
			fmt.Printf("  %s %-16s %s\n", dangerB(symbolCross), v.name, dangerB("VULNERABLE"))
			hasCritical = true
		} else {
			fmt.Printf("  %s %-16s %s\n", success(symbolCheck), v.name, muted("Seguro"))
		}
	}

	fmt.Println()
	if hasCritical {
		fmt.Println(style("  "+symbolCross+" CRÍTICO: Vulnerabilidades explotables detectadas", bold(), brightRed()))
	} else {
		fmt.Println(style("  "+symbolCheck+" Sin vulnerabilidades críticas", bold(), green()))
	}

	// ═══════════════════════════════════════════════════════════════════════
	// VULNERABILIDADES INFORMATIVAS - Históricas o típicamente mitigadas
	// ═══════════════════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println(style("  Información Adicional", bold(), dim()))
	fmt.Println(muted("  (Históricas o mitigadas en navegadores modernos)"))
	fmt.Println()

	// BEAST, POODLE, FREAK, Logjam son históricas - mitigadas en TLS 1.1+
	// y en todos los navegadores modernos (client-side mitigation)
	infoVulns := []struct {
		name     string
		detected bool
		note     string
	}{
		{"BEAST", details.VulnBeast, "Mitigado en TLS 1.1+ y navegadores"},
		{"POODLE (SSL3)", details.Poodle, "SSL 3.0 deprecado"},
		{"FREAK", details.Freak, "Export ciphers obsoletos"},
		{"Logjam", details.Logjam, "DHE débil"},
	}

	infoNumeric := []struct {
		name      string
		value     int
		threshold int
		note      string
	}{
		{"Zombie POODLE", details.ZombiePoodle, 2, "Variante CBC"},
		{"GOLDENDOODLE", details.GoldenDoodle, 4, "Variante CBC"},
		{"Sleeping POODLE", details.SleepingPoodle, 10, "Variante CBC"},
	}

	for _, v := range infoVulns {
		if v.detected {
			fmt.Printf("  %s %-16s %s %s\n", warning(symbolWarning), v.name, warning("Detectado"), muted("- "+v.note))
		} else {
			fmt.Printf("  %s %-16s %s\n", muted(symbolCircle), v.name, muted("No detectado"))
		}
	}

	for _, v := range infoNumeric {
		if v.value >= v.threshold {
			fmt.Printf("  %s %-16s %s %s\n", warning(symbolWarning), v.name, warning("Detectado"), muted("- "+v.note))
		} else {
			fmt.Printf("  %s %-16s %s\n", muted(symbolCircle), v.name, muted("No detectado"))
		}
	}
}

// disableColors desactiva todos los colores (para pipes o --no-color)
func disableColors() {
	colorEnabled = false
}
