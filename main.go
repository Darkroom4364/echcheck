package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

var version = "dev"

// Check name constants used in report output and JSON.
const (
	checkDNS         = "DNS HTTPS Record"
	checkECHConfig   = "ECHConfig Parse"
	checkVersion     = "ECHConfig Version"
	checkKEM         = "KEM"
	checkKDFAEAD     = "KDF / AEAD"
	checkPublicName  = "Public Name"
	checkConfigID    = "Config ID"
	checkMaxNameLen  = "Max Name Length"
	checkNegotiation = "ECH Negotiation"
	checkCertInner   = "Certificate (inner)"
	checkRetry       = "Retry Configs"
	checkGREASE      = "GREASE Handling"
	checkSNI         = "SNI Leakage"
	checkCertOuter   = "Certificate (outer)"
)

func main() {
	jsonOutput := flag.Bool("json", false, "output JSON for CI/CD")
	resolver := flag.String("resolver", "1.1.1.1:53", "DNS resolver address")
	dohURL := flag.String("doh", "", "DNS-over-HTTPS endpoint (e.g. https://1.1.1.1/dns-query)")
	timeout := flag.Duration("timeout", 10*time.Second, "connection timeout")
	verbose := flag.Bool("verbose", false, "show detailed handshake info")
	flag.BoolVar(verbose, "v", false, "show detailed handshake info (shorthand)")
	batch := flag.Bool("batch", false, "read domains from stdin, one per line")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: echcheck [flags] <domain[:port]>\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("echcheck", version)
		return
	}

	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: timeout must be a positive duration")
		os.Exit(2)
	}

	dnsOpts := DNSOptions{Resolver: *resolver, DoHURL: *dohURL, Timeout: *timeout}

	if *batch {
		if flag.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "warning: domain argument ignored when --batch is used")
		}
		os.Exit(runBatch(dnsOpts, *timeout, *verbose, *jsonOutput))
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	domain, port := parseTarget(flag.Arg(0))
	report := run(domain, port, dnsOpts, *timeout, *verbose)

	if *jsonOutput {
		report.PrintJSON()
	} else {
		report.PrintText()
	}
	os.Exit(report.ExitCode())
}

func parseTarget(target string) (string, string) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, "443"
	}
	if port == "" {
		port = "443"
	}
	return host, port
}

func runBatch(dnsOpts DNSOptions, timeout time.Duration, verbose, jsonOutput bool) int {
	scanner := bufio.NewScanner(os.Stdin)
	var reports []*Report
	exitCode := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain, port := parseTarget(line)
		report := run(domain, port, dnsOpts, timeout, verbose)
		reports = append(reports, report)

		if !jsonOutput {
			report.PrintText()
		}
		if ec := report.ExitCode(); ec > exitCode {
			exitCode = ec
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
	}

	if len(reports) == 0 {
		fmt.Fprintln(os.Stderr, "error: no domains found in batch input")
		return 2
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
		}
	}
	return exitCode
}

func run(domain, port string, dnsOpts DNSOptions, timeout time.Duration, verbose bool) *Report {
	report := &Report{Domain: domain}

	// Step 1: DNS HTTPS record
	echConfigList, ttl, err := QueryHTTPSRecord(domain, dnsOpts)
	if err != nil {
		report.Add(checkDNS, StatusFail, fmt.Sprintf("Error: %v", err))
		report.Finalize()
		return report
	}
	if echConfigList == nil {
		report.ECHSupported = false
		report.Add(checkDNS, StatusFail, "No HTTPS RR found")
		report.Add(checkNegotiation, StatusSkip, "Skipped (no ECHConfig)")
		report.Finalize()
		return report
	}
	report.ECHSupported = true
	report.Add(checkDNS, StatusPass, fmt.Sprintf("Found (TTL: %ds)", ttl))

	// Step 2: Parse ECHConfig
	configs, parseErr := ParseECHConfigList(echConfigList)
	if parseErr != nil {
		report.Add(checkECHConfig, StatusFail, fmt.Sprintf("Error: %v", parseErr))
		report.Finalize()
		return report
	}
	if len(configs) == 0 {
		report.Add(checkECHConfig, StatusFail, "No configs in ECHConfigList")
		report.Finalize()
		return report
	}

	cfg := configs[0]
	reportECHConfig(report, cfg, domain, configs, echConfigList, verbose)

	// Step 3: ECH Negotiation
	negResult, err := CheckECHNegotiation(domain, port, echConfigList, timeout)
	if err != nil {
		report.Add(checkNegotiation, StatusFail, fmt.Sprintf("Error: %v", err))
		report.Finalize()
		return report
	}
	reportNegotiation(report, negResult, domain, verbose)

	// Step 4: Retry Configs
	reportRetryConfigs(report, domain, port, echConfigList, timeout)

	// Step 5: GREASE / Non-ECH Fallback
	reportFallback(report, domain, port, timeout)

	// Step 6: SNI Leakage + Certificate (outer)
	reportSNILeakage(report, cfg.PublicName, port, domain, timeout)

	report.Finalize()
	return report
}

func reportECHConfig(report *Report, cfg ECHConfigInfo, domain string, configs []ECHConfigInfo, echConfigList []byte, verbose bool) {
	report.Add(checkVersion, StatusPass, fmt.Sprintf("0x%04x", cfg.Version))
	report.Add(checkKEM, StatusPass, fmt.Sprintf("%s (0x%04x)", cfg.KEM, cfg.KEMID))
	if len(cfg.CipherSuites) > 0 {
		cs := cfg.CipherSuites[0]
		report.Add(checkKDFAEAD, StatusPass, fmt.Sprintf("%s / %s", cs.KDF, cs.AEAD))
	}
	report.Add(checkPublicName, StatusPass, cfg.PublicName)
	report.Add(checkConfigID, StatusPass, fmt.Sprintf("0x%02x", cfg.ConfigID))

	mnlStatus := StatusPass
	mnlDetail := fmt.Sprintf("%d", cfg.MaxNameLength)
	if cfg.MaxNameLength == 0 {
		mnlDetail += " (server-managed padding)"
	} else if cfg.MaxNameLength < uint8(len(domain)) {
		mnlStatus = StatusWarn
		mnlDetail += fmt.Sprintf(" (shorter than domain length %d)", len(domain))
	}
	report.Add(checkMaxNameLen, mnlStatus, mnlDetail)

	if verbose {
		fmt.Fprintf(os.Stderr, "\n  [verbose] ECHConfigList: %d configs, %d bytes\n", len(configs), len(echConfigList))
		fmt.Fprintf(os.Stderr, "  [verbose] Public key: %d bytes\n", cfg.PublicKeyLen)
		fmt.Fprintf(os.Stderr, "  [verbose] Cipher suites: %d\n", len(cfg.CipherSuites))
		for i, cs := range cfg.CipherSuites {
			fmt.Fprintf(os.Stderr, "  [verbose]   [%d] %s / %s\n", i, cs.KDF, cs.AEAD)
		}
	}
}

func reportNegotiation(report *Report, negResult *NegotiationResult, domain string, verbose bool) {
	if negResult.Accepted {
		detail := fmt.Sprintf("Accepted (%s)", negResult.TLSVersion)
		if !negResult.TLS13 {
			report.Add(checkNegotiation, StatusWarn, detail+" — ECH requires TLS 1.3")
		} else {
			report.Add(checkNegotiation, StatusPass, detail)
		}
	} else {
		report.Add(checkNegotiation, StatusFail, "Rejected by server")
	}

	if verbose && negResult.Accepted && len(negResult.PeerCerts) > 0 {
		cert := negResult.PeerCerts[0]
		fmt.Fprintf(os.Stderr, "  [verbose] Peer cert subject: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(os.Stderr, "  [verbose] Peer cert SANs: %v\n", cert.DNSNames)
		fmt.Fprintf(os.Stderr, "  [verbose] Cipher suite: %s\n", negResult.CipherSuite)
	}

	if negResult.Accepted && len(negResult.PeerCerts) > 0 {
		innerCert := negResult.PeerCerts[0]
		if err := innerCert.VerifyHostname(domain); err == nil {
			report.Add(checkCertInner, StatusPass, fmt.Sprintf("Valid for %s", domain))
		} else {
			report.Add(checkCertInner, StatusFail, fmt.Sprintf("Not valid for %s: %v", domain, err))
		}
	}
}

func reportRetryConfigs(report *Report, domain, port string, echConfigList []byte, timeout time.Duration) {
	retryResult, err := CheckRetryConfigs(domain, port, echConfigList, timeout)
	if err != nil {
		report.Add(checkRetry, StatusWarn, fmt.Sprintf("Error: %v", err))
		return
	}
	if retryResult.RetryConfigsReceived && retryResult.RetryConfigsValid {
		detail := "Server returns valid retry_configs"
		if retryResult.RetrySucceeded {
			detail += " (retry succeeded)"
		} else if retryResult.RetryError != nil {
			detail += fmt.Sprintf(" (retry failed: %v)", retryResult.RetryError)
		}
		report.Add(checkRetry, StatusPass, detail)
	} else if retryResult.RetryConfigsReceived {
		detail := "Received but failed to parse"
		if retryResult.ParseError != nil {
			detail += fmt.Sprintf(": %v", retryResult.ParseError)
		}
		report.Add(checkRetry, StatusWarn, detail)
	} else {
		report.Add(checkRetry, StatusWarn, "Server did not send retry_configs")
	}
}

func reportFallback(report *Report, domain, port string, timeout time.Duration) {
	fallbackResult, err := CheckFallback(domain, port, timeout)
	if err != nil {
		report.Add(checkGREASE, StatusWarn, fmt.Sprintf("Error: %v", err))
		return
	}
	if fallbackResult.HandshakeSucceeded {
		report.Add(checkGREASE, StatusPass, "Server ignores absent ECH gracefully")
	} else {
		detail := "Server rejects non-ECH clients"
		if fallbackResult.ErrorDetail != "" {
			detail += ": " + fallbackResult.ErrorDetail
		}
		report.Add(checkGREASE, StatusFail, detail)
	}
}

func reportSNILeakage(report *Report, publicName, port, domain string, timeout time.Duration) {
	if publicName == "" || publicName == domain {
		report.Add(checkSNI, StatusSkip, "public_name same as domain or empty")
		report.Add(checkCertOuter, StatusSkip, "public_name same as domain or empty")
		return
	}
	leaks, certDomains, err := CheckSNILeakage(publicName, port, domain, timeout)
	if err != nil {
		report.Add(checkSNI, StatusWarn, fmt.Sprintf("Error: %v", err))
		report.Add(checkCertOuter, StatusWarn, "Skipped (SNI check errored)")
	} else if leaks {
		report.Add(checkSNI, StatusFail, fmt.Sprintf("Outer cert covers inner domain (domains: %v)", certDomains))
		report.Add(checkCertOuter, StatusFail, fmt.Sprintf("Covers %s (should only cover %s)", domain, publicName))
	} else {
		report.Add(checkSNI, StatusPass, fmt.Sprintf("Outer SNI = %s (no leak)", publicName))
		report.Add(checkCertOuter, StatusPass, fmt.Sprintf("Valid for %s", publicName))
	}
}
