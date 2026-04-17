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
		report.Add("DNS HTTPS Record", StatusFail, fmt.Sprintf("Error: %v", err))
		report.Finalize()
		return report
	}
	if echConfigList == nil {
		report.ECHSupported = false
		report.Add("DNS HTTPS Record", StatusFail, "No HTTPS RR found")
		report.Add("ECH Negotiation", StatusSkip, "Skipped (no ECHConfig)")
		report.Finalize()
		return report
	}
	report.ECHSupported = true
	report.Add("DNS HTTPS Record", StatusPass, fmt.Sprintf("Found (TTL: %ds)", ttl))

	// Step 2: Parse ECHConfig
	configs, parseErr := ParseECHConfigList(echConfigList)
	if parseErr != nil {
		report.Add("ECHConfig Parse", StatusFail, fmt.Sprintf("Error: %v", parseErr))
		report.Finalize()
		return report
	}
	if len(configs) == 0 {
		report.Add("ECHConfig Parse", StatusFail, "No configs in ECHConfigList")
		report.Finalize()
		return report
	}

	cfg := configs[0] // use first config for display
	report.Add("ECHConfig Version", StatusPass, fmt.Sprintf("0x%04x", cfg.Version))
	report.Add("KEM", StatusPass, fmt.Sprintf("%s (0x%04x)", cfg.KEM, cfg.KEMID))
	if len(cfg.CipherSuites) > 0 {
		cs := cfg.CipherSuites[0]
		report.Add("KDF / AEAD", StatusPass, fmt.Sprintf("%s / %s", cs.KDF, cs.AEAD))
	}
	report.Add("Public Name", StatusPass, cfg.PublicName)
	report.Add("Config ID", StatusPass, fmt.Sprintf("0x%02x", cfg.ConfigID))

	mnlStatus := StatusPass
	mnlDetail := fmt.Sprintf("%d", cfg.MaxNameLength)
	if cfg.MaxNameLength == 0 {
		mnlDetail += " (server-managed padding)"
	} else if cfg.MaxNameLength < uint8(len(domain)) {
		mnlStatus = StatusWarn
		mnlDetail += fmt.Sprintf(" (shorter than domain length %d)", len(domain))
	}
	report.Add("Max Name Length", mnlStatus, mnlDetail)

	if verbose {
		fmt.Fprintf(os.Stderr, "\n  [verbose] ECHConfigList: %d configs, %d bytes\n", len(configs), len(echConfigList))
		fmt.Fprintf(os.Stderr, "  [verbose] Public key: %d bytes\n", cfg.PublicKeyLen)
		fmt.Fprintf(os.Stderr, "  [verbose] Cipher suites: %d\n", len(cfg.CipherSuites))
		for i, cs := range cfg.CipherSuites {
			fmt.Fprintf(os.Stderr, "  [verbose]   [%d] %s / %s\n", i, cs.KDF, cs.AEAD)
		}
	}

	// Step 3: ECH Negotiation
	negResult, err := CheckECHNegotiation(domain, port, echConfigList, timeout)
	if err != nil {
		report.Add("ECH Negotiation", StatusFail, fmt.Sprintf("Error: %v", err))
		report.Finalize()
		return report
	}
	if negResult.Accepted {
		detail := fmt.Sprintf("Accepted (%s)", negResult.TLSVersion)
		if !negResult.TLS13 {
			report.Add("ECH Negotiation", StatusWarn, detail+" — ECH requires TLS 1.3")
		} else {
			report.Add("ECH Negotiation", StatusPass, detail)
		}
	} else {
		report.Add("ECH Negotiation", StatusFail, "Rejected by server")
	}

	if verbose && negResult.Accepted && len(negResult.PeerCerts) > 0 {
		cert := negResult.PeerCerts[0]
		fmt.Fprintf(os.Stderr, "  [verbose] Peer cert subject: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(os.Stderr, "  [verbose] Peer cert SANs: %v\n", cert.DNSNames)
		fmt.Fprintf(os.Stderr, "  [verbose] Cipher suite: %s\n", negResult.CipherSuite)
	}

	// Certificate (inner): verify the ECH-negotiated cert covers the target domain
	if negResult.Accepted && len(negResult.PeerCerts) > 0 {
		innerCert := negResult.PeerCerts[0]
		if err := innerCert.VerifyHostname(domain); err == nil {
			report.Add("Certificate (inner)", StatusPass, fmt.Sprintf("Valid for %s", domain))
		} else {
			report.Add("Certificate (inner)", StatusFail, fmt.Sprintf("Not valid for %s: %v", domain, err))
		}
	}

	// Step 4: Retry Configs
	retryResult, err := CheckRetryConfigs(domain, port, echConfigList, timeout)
	if err != nil {
		report.Add("Retry Configs", StatusWarn, fmt.Sprintf("Error: %v", err))
	} else if retryResult.RetryConfigsReceived && retryResult.RetryConfigsValid {
		detail := "Server returns valid retry_configs"
		if retryResult.RetrySucceeded {
			detail += " (retry succeeded)"
		} else if retryResult.RetryError != nil {
			detail += fmt.Sprintf(" (retry failed: %v)", retryResult.RetryError)
		}
		report.Add("Retry Configs", StatusPass, detail)
	} else if retryResult.RetryConfigsReceived {
		detail := "Received but failed to parse"
		if retryResult.ParseError != nil {
			detail += fmt.Sprintf(": %v", retryResult.ParseError)
		}
		report.Add("Retry Configs", StatusWarn, detail)
	} else {
		report.Add("Retry Configs", StatusWarn, "Server did not send retry_configs")
	}

	// Step 5: GREASE / Non-ECH Fallback
	fallbackResult, err := CheckFallback(domain, port, timeout)
	if err != nil {
		report.Add("GREASE Handling", StatusWarn, fmt.Sprintf("Error: %v", err))
	} else if fallbackResult.HandshakeSucceeded {
		report.Add("GREASE Handling", StatusPass, "Server ignores absent ECH gracefully")
	} else {
		detail := "Server rejects non-ECH clients"
		if fallbackResult.ErrorDetail != "" {
			detail += ": " + fallbackResult.ErrorDetail
		}
		report.Add("GREASE Handling", StatusFail, detail)
	}

	// Step 6: SNI Leakage + Certificate (outer)
	if cfg.PublicName != "" && cfg.PublicName != domain {
		leaks, certDomains, err := CheckSNILeakage(cfg.PublicName, port, domain, timeout)
		if err != nil {
			report.Add("SNI Leakage", StatusWarn, fmt.Sprintf("Error: %v", err))
			report.Add("Certificate (outer)", StatusWarn, "Skipped (SNI check errored)")
		} else if leaks {
			report.Add("SNI Leakage", StatusFail, fmt.Sprintf("Outer cert covers inner domain (domains: %v)", certDomains))
			report.Add("Certificate (outer)", StatusFail, fmt.Sprintf("Covers %s (should only cover %s)", domain, cfg.PublicName))
		} else {
			report.Add("SNI Leakage", StatusPass, fmt.Sprintf("Outer SNI = %s (no leak)", cfg.PublicName))
			report.Add("Certificate (outer)", StatusPass, fmt.Sprintf("Valid for %s", cfg.PublicName))
		}
	} else {
		report.Add("SNI Leakage", StatusSkip, "public_name same as domain or empty")
		report.Add("Certificate (outer)", StatusSkip, "public_name same as domain or empty")
	}

	report.Finalize()
	return report
}
