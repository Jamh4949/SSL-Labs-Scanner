/*
SSL Labs Scanner - Technical Challenge

This program analyzes the TLS security configuration of a domain using
the SSL Labs public API v4. It displays the SSL grade, identifies critical
vulnerabilities, and differentiates between exploitable and historical/mitigated issues.

Usage:

	go run main.go -email your@company.com -host domain.com

Requirements:
  - Email must be pre-registered with SSL Labs (see README.md)
  - No external dependencies (stdlib only)

Author: Jose Martínez
Con mucho cariño para el Semillero Nebula
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
// ANSI Colors & Styles - No external dependencies required
// ============================================================================

// colorEnabled controls whether ANSI escape codes are used for terminal output.
// Set to false via --no-color flag or NO_COLOR environment variable.
var colorEnabled = true

// ANSI escape codes for terminal text formatting.
// Reference: https://en.wikipedia.org/wiki/ANSI_escape_code
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

// Unicode symbols for visual indicators in output.
// Note: These display regardless of colorEnabled setting.
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

// Color accessor functions - return ANSI codes only when colorEnabled is true.
// This pattern allows graceful degradation when output is piped or redirected.
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

// style applies multiple ANSI style codes to a text string.
// Returns plain text if colorEnabled is false.
func style(text string, styles ...string) string {
	if !colorEnabled || len(styles) == 0 {
		return text
	}
	prefix := strings.Join(styles, "")
	return prefix + text + ansiReset
}

// Semantic style helpers for common message types.
// These provide consistent coloring throughout the application.
func success(text string) string  { return style(text, green()) }
func successB(text string) string { return style(text, bold(), green()) } // Bold success
func warning(text string) string  { return style(text, yellow()) }
func warningB(text string) string { return style(text, bold(), yellow()) } // Bold warning
func danger(text string) string   { return style(text, red()) }
func dangerB(text string) string  { return style(text, bold(), red()) } // Bold danger
func info(text string) string     { return style(text, cyan()) }
func infoB(text string) string    { return style(text, bold(), cyan()) } // Bold info
func muted(text string) string    { return style(text, gray()) }         // Dimmed/secondary text
func header(text string) string   { return style(text, bold(), brightCyan()) }
func label(text string) string    { return style(text, dim()) } // Field labels

// line generates a decorative horizontal line of specified length.
func line(length int) string {
	return muted(strings.Repeat(symbolLine, length))
}

// ============================================================================
// Main - Application entry point
// ============================================================================

func main() {
	// Parse command-line flags
	emailFlag := flag.String("email", "", "Email registered with SSL Labs (or use SSLLABS_EMAIL env var)")
	host := flag.String("host", "", "Domain to analyze (required)")
	timeout := flag.Duration("timeout", 10*time.Minute, "Maximum timeout for the analysis")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	flag.Parse()

	// Disable colors if requested or if not running in a terminal
	if *noColor || os.Getenv("NO_COLOR") != "" {
		disableColors()
	}

	// Email priority: command-line flag > environment variable
	email := *emailFlag
	if email == "" {
		email = os.Getenv("SSLLABS_EMAIL")
	}

	// Validate required arguments
	if email == "" || *host == "" {
		fmt.Println(dangerB("Error: ") + "Required parameters: " + info("-email") + " (or " + info("SSLLABS_EMAIL") + ") and " + info("-host"))
		fmt.Println()
		flag.Usage()
		os.Exit(1)
	}

	// Validate email format (warn if using free email provider)
	if warnings := client.ValidateEmail(email); len(warnings) > 0 {
		for _, w := range warnings {
			fmt.Println(warningB(symbolWarning+" ") + w)
		}
		fmt.Println()
	}

	// Create context with cancellation (Ctrl+C) and timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Handle interrupt signals (Ctrl+C, SIGTERM) for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		fmt.Println(warningB(symbolWarning + " Cancelling analysis..."))
		cancel()
	}()

	// Create SSL Labs client
	c := client.New(email)

	// Display application banner
	printBanner()

	// Verify SSL Labs API availability
	fmt.Println(info(symbolArrow) + " Checking SSL Labs availability...")

	apiInfo, err := c.Info(ctx)
	if err != nil {
		fmt.Println(dangerB(symbolCross+" Error: ") + fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	fmt.Println(successB(symbolCheck) + " SSL Labs " + success("available"))
	fmt.Println(muted("  Engine: "+apiInfo.EngineVersion) + muted(" │ Criteria: "+apiInfo.CriteriaVersion))
	fmt.Println(muted(fmt.Sprintf("  Assessments: %d/%d", apiInfo.CurrentAssessments, apiInfo.MaxAssessments)))

	// Display cool-off period if applicable
	coolOff := time.Duration(apiInfo.NewAssessmentCoolOff) * time.Millisecond
	if coolOff > 0 {
		fmt.Println(muted(fmt.Sprintf("  Cool-off: %v", coolOff)))
	}
	fmt.Println()

	// Start analysis with polling
	fmt.Println(header(symbolDot+" Analyzing: ") + infoB(*host))
	fmt.Println(muted("  (This may take several minutes... Ctrl+C to cancel)"))
	fmt.Println()

	result, err := c.AnalyzeWithPolling(ctx, *host, coolOff, func(status, msg string) {
		statusColor := getStatusColor(status)
		fmt.Printf("  %s %s\n", style("["+status+"]", statusColor), muted(msg))
	})

	// Display updated rate limiting information
	rateLimit := c.GetRateLimitInfo()
	if rateLimit.MaxAssessments > 0 {
		fmt.Println()
		fmt.Println(muted(fmt.Sprintf("  Rate limit: %d/%d assessments",
			rateLimit.CurrentAssessments, rateLimit.MaxAssessments)))
	}

	if err != nil {
		fmt.Println()
		fmt.Println(dangerB(symbolCross+" Error: ") + fmt.Sprintf("%v", err))
		// If partial results exist, display them
		if result != nil && len(result.Endpoints) > 0 {
			fmt.Println()
			fmt.Println(warningB("═══ PARTIAL RESULTS ═══"))
			printResults(result)
		}
		os.Exit(1)
	}

	// Display final results
	fmt.Println()
	printResults(result)
}

// ============================================================================
// Output Functions - Display formatting for analysis results
// ============================================================================

// printBanner displays the application header/banner.
func printBanner() {
	fmt.Println()
	fmt.Println(header("╔══════════════════════════════════════╗"))
	fmt.Println(header("║") + "      " + style("SSL Labs Scanner", bold(), brightCyan()) + "  " + muted("v1.0") + "      " + header("║"))
	fmt.Println(header("║") + "   " + muted("TLS Security Analysis Tool") + "      " + header("║"))
	fmt.Println(header("╚══════════════════════════════════════╝"))
	fmt.Println()
}

// getStatusColor returns the appropriate ANSI color code for a given status.
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

// printResults displays the complete analysis results with formatting.
func printResults(result *models.Host) {
	fmt.Println(header("╔══════════════════════════════════════╗"))
	fmt.Println(header("║") + "           " + style("RESULTS", bold(), white()) + "                 " + header("║"))
	fmt.Println(header("╚══════════════════════════════════════╝"))
	fmt.Println()

	// Host information
	fmt.Println(label("  Domain: ") + infoB(result.Host))
	if result.Port > 0 {
		fmt.Println(label("  Port:   ") + info(fmt.Sprintf("%d", result.Port)))
	}
	fmt.Println()

	if len(result.Endpoints) == 0 {
		fmt.Println(warning("  No endpoints found to analyze."))
		return
	}

	for i, endpoint := range result.Endpoints {
		printEndpoint(i+1, endpoint)
	}
}

// printEndpoint displays detailed information for a single endpoint.
func printEndpoint(num int, endpoint models.Endpoint) {
	fmt.Println(line(42))
	fmt.Println(style(fmt.Sprintf("  %s Endpoint %d", symbolBox, num), bold()))
	fmt.Println(line(42))
	fmt.Println()

	// IP and server name
	fmt.Println(label("  IP:     ") + info(endpoint.IPAddress))
	if endpoint.ServerName != "" {
		fmt.Println(label("  Server: ") + muted(endpoint.ServerName))
	}
	fmt.Println()

	// Grade - the most important metric
	printGrade(endpoint.Grade)

	if endpoint.GradeTrustIgnored != "" && endpoint.GradeTrustIgnored != endpoint.Grade {
		fmt.Println(label("  Grade (ignoring trust): ") + formatGradeCompact(endpoint.GradeTrustIgnored))
	}

	if endpoint.FutureGrade != "" {
		fmt.Println(label("  Future Grade: ") + formatGradeCompact(endpoint.FutureGrade))
	}

	// Warnings and exceptional status
	if endpoint.HasWarnings {
		fmt.Println()
		fmt.Println(warningB("  "+symbolWarning+" Warnings") + warning(" that may affect the score"))
	}

	if endpoint.IsExceptional {
		fmt.Println()
		fmt.Println(style("  "+symbolStar+" Exceptional configuration", bold(), brightGreen()))
	}

	// Vulnerability assessment
	if endpoint.Details != nil {
		fmt.Println()
		printVulnerabilities(endpoint.Details)
	}

	fmt.Println()
}

// printGrade displays the security grade with prominent visual formatting.
// Grades range from A+ (best) to F (worst), with T for trust issues and M for certificate mismatch.
func printGrade(grade string) {
	if grade == "" {
		fmt.Println(label("  Grade:  ") + muted("(pending)"))
		return
	}

	var gradeStyle, symbol, status string

	switch {
	case grade == "A+":
		gradeStyle = style(grade, bold(), brightGreen())
		symbol = style(symbolStar, brightGreen())
		status = success("Excellent")
	case grade == "A":
		gradeStyle = style(grade, bold(), green())
		symbol = style(symbolCheck, green())
		status = success("Very Good")
	case grade == "A-":
		gradeStyle = style(grade, bold(), green())
		symbol = style(symbolCheck, green())
		status = success("Good")
	case grade == "B":
		gradeStyle = style(grade, bold(), yellow())
		symbol = style(symbolCircle, yellow())
		status = warning("Acceptable")
	case grade == "C":
		gradeStyle = style(grade, bold(), yellow())
		symbol = style(symbolWarning, yellow())
		status = warning("Needs Improvement")
	case grade == "D" || grade == "E":
		gradeStyle = style(grade, bold(), red())
		symbol = style(symbolWarning, red())
		status = danger("Insecure")
	case grade == "F":
		gradeStyle = style(grade, bold(), brightRed())
		symbol = style(symbolCross, brightRed())
		status = dangerB("Critical")
	case grade == "T":
		gradeStyle = style(grade, bold(), red())
		symbol = style(symbolCross, red())
		status = danger("Not Trusted")
	case grade == "M":
		gradeStyle = style(grade, bold(), red())
		symbol = style(symbolWarning, red())
		status = danger("Certificate Mismatch")
	default:
		gradeStyle = style(grade, bold())
		symbol = "?"
		status = muted("Unknown")
	}

	fmt.Println()
	fmt.Println(style("  ┌─────────────────────────────┐", dim()))
	fmt.Printf("  │   Grade: %s  %s         │\n", gradeStyle, symbol)
	fmt.Printf("  │   %s                  │\n", status)
	fmt.Println(style("  └─────────────────────────────┘", dim()))
	fmt.Println()
}

// formatGradeCompact returns a colored grade string without the decorative box.
// Used for secondary grade displays (trust-ignored, future grade).
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

// printVulnerabilities displays the vulnerability assessment results.
// Separates CRITICAL vulnerabilities (active exploits requiring action) from
// INFORMATIONAL ones (historical or mitigated in modern environments).
func printVulnerabilities(details *models.EndpointDetails) {
	// ═══════════════════════════════════════════════════════════════════════
	// CRITICAL VULNERABILITIES - Active exploits requiring immediate action
	// ═══════════════════════════════════════════════════════════════════════
	fmt.Println(style("  Critical Vulnerabilities", bold(), underline()))
	fmt.Println()

	// Boolean-based critical vulnerabilities
	criticalVulns := []struct {
		name       string
		vulnerable bool
	}{
		{"Heartbleed", details.Heartbleed}, // CVE-2014-0160 - OpenSSL memory disclosure
		{"DROWN", details.DrownVulnerable}, // CVE-2016-0800 - Cross-protocol attack via SSLv2
	}

	// Integer-based critical vulnerabilities (threshold indicates vulnerability)
	criticalNumeric := []struct {
		name      string
		value     int
		threshold int
	}{
		{"ROBOT", details.Bleichenbacher, 2},               // Return Of Bleichenbacher's Oracle Threat
		{"OpenSSL CCS", details.OpenSslCcs, 2},             // CVE-2014-0224 - CCS Injection
		{"Lucky Minus 20", details.OpenSSLLuckyMinus20, 2}, // CVE-2016-2107 - Padding oracle
		{"Ticketbleed", details.Ticketbleed, 2},            // CVE-2016-9244 - Session ticket leak
	}

	hasCritical := false

	for _, v := range criticalVulns {
		if v.vulnerable {
			fmt.Printf("  %s %-16s %s\n", dangerB(symbolCross), v.name, dangerB("VULNERABLE"))
			hasCritical = true
		} else {
			fmt.Printf("  %s %-16s %s\n", success(symbolCheck), v.name, muted("Secure"))
		}
	}

	for _, v := range criticalNumeric {
		if v.value >= v.threshold {
			fmt.Printf("  %s %-16s %s\n", dangerB(symbolCross), v.name, dangerB("VULNERABLE"))
			hasCritical = true
		} else {
			fmt.Printf("  %s %-16s %s\n", success(symbolCheck), v.name, muted("Secure"))
		}
	}

	fmt.Println()
	if hasCritical {
		fmt.Println(style("  "+symbolCross+" CRITICAL: Exploitable vulnerabilities detected", bold(), brightRed()))
	} else {
		fmt.Println(style("  "+symbolCheck+" No critical vulnerabilities found", bold(), green()))
	}

	// ═══════════════════════════════════════════════════════════════════════
	// INFORMATIONAL VULNERABILITIES - Historical or typically mitigated
	// ═══════════════════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println(style("  Additional Information", bold(), dim()))
	fmt.Println(muted("  (Historical or mitigated in modern browsers)"))
	fmt.Println()

	// BEAST, POODLE, FREAK, Logjam are historical vulnerabilities.
	// These are mitigated in TLS 1.1+ and all modern browsers via client-side protections.
	infoVulns := []struct {
		name     string
		detected bool
		note     string
	}{
		{"BEAST", details.VulnBeast, "Mitigated in TLS 1.1+ and browsers"},
		{"POODLE (SSL3)", details.Poodle, "SSL 3.0 deprecated"},
		{"FREAK", details.Freak, "Export ciphers obsolete"},
		{"Logjam", details.Logjam, "Weak DHE parameters"},
	}

	// Numeric informational vulnerabilities (CBC-related variants)
	infoNumeric := []struct {
		name      string
		value     int
		threshold int
		note      string
	}{
		{"Zombie POODLE", details.ZombiePoodle, 2, "CBC variant"},
		{"GOLDENDOODLE", details.GoldenDoodle, 4, "CBC variant"},
		{"Sleeping POODLE", details.SleepingPoodle, 10, "CBC variant"},
	}

	for _, v := range infoVulns {
		if v.detected {
			fmt.Printf("  %s %-16s %s %s\n", warning(symbolWarning), v.name, warning("Detected"), muted("- "+v.note))
		} else {
			fmt.Printf("  %s %-16s %s\n", muted(symbolCircle), v.name, muted("Not detected"))
		}
	}

	for _, v := range infoNumeric {
		if v.value >= v.threshold {
			fmt.Printf("  %s %-16s %s %s\n", warning(symbolWarning), v.name, warning("Detected"), muted("- "+v.note))
		} else {
			fmt.Printf("  %s %-16s %s\n", muted(symbolCircle), v.name, muted("Not detected"))
		}
	}
}

// disableColors turns off all ANSI color output.
// Called when --no-color flag is set or NO_COLOR environment variable exists.
func disableColors() {
	colorEnabled = false
}
