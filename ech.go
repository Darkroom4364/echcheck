package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

func dialTLS(host, port string, timeout time.Duration, cfg *tls.Config) (*tls.Conn, error) {
	addr := net.JoinHostPort(host, port)
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
}

// NegotiationResult holds the outcome of an ECH negotiation attempt.
type NegotiationResult struct {
	Accepted    bool
	TLSVersion  string
	CipherSuite string
	PeerCerts   []*x509.Certificate
}

// RetryResult holds the outcome of a retry_configs test.
type RetryResult struct {
	RetryConfigsReceived bool
	RetryConfigsValid    bool
	RetrySucceeded       bool
	RetryConfigs         []ECHConfigInfo
}

// FallbackResult holds the outcome of a non-ECH fallback test.
type FallbackResult struct {
	HandshakeSucceeded bool
	CertDomains        []string
}

// CheckECHNegotiation attempts a TLS connection with ECH and reports whether
// the server accepted it.
func CheckECHNegotiation(host, port string, echConfigList []byte, timeout time.Duration) (*NegotiationResult, error) {
	conn, err := dialTLS(host, port, timeout, &tls.Config{
		ServerName:                     host,
		EncryptedClientHelloConfigList: echConfigList,
	})
	if err != nil {
		var echErr *tls.ECHRejectionError
		if errors.As(err, &echErr) {
			return &NegotiationResult{Accepted: false}, nil
		}
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return &NegotiationResult{
		Accepted:    true,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		PeerCerts:   state.PeerCertificates,
	}, nil
}

// CheckRetryConfigs connects with a corrupted ECHConfig to trigger a retry_configs
// response from the server, then validates and optionally retries with them.
func CheckRetryConfigs(host, port string, echConfigList []byte, timeout time.Duration) (*RetryResult, error) {
	// Corrupt the config by flipping a byte in the public key area.
	// We need a copy to avoid mutating the original.
	corrupted := make([]byte, len(echConfigList))
	copy(corrupted, echConfigList)
	if len(corrupted) > 20 {
		corrupted[20] ^= 0xff
	}

	_, err := dialTLS(host, port, timeout, &tls.Config{
		ServerName:                     host,
		EncryptedClientHelloConfigList: corrupted,
	})

	var echErr *tls.ECHRejectionError
	if !errors.As(err, &echErr) {
		if err == nil {
			// Server accepted corrupted config? Unexpected.
			return &RetryResult{RetryConfigsReceived: false}, nil
		}
		return nil, fmt.Errorf("expected ECH rejection, got: %w", err)
	}

	result := &RetryResult{}
	if len(echErr.RetryConfigList) == 0 {
		return result, nil
	}
	result.RetryConfigsReceived = true

	// Parse the retry configs to validate them
	configs, parseErr := ParseECHConfigList(echErr.RetryConfigList)
	if parseErr != nil {
		return result, nil
	}
	result.RetryConfigs = configs
	result.RetryConfigsValid = len(configs) > 0

	// Try connecting with the retry configs
	conn, retryErr := dialTLS(host, port, timeout, &tls.Config{
		ServerName:                     host,
		EncryptedClientHelloConfigList: echErr.RetryConfigList,
	})
	if retryErr == nil {
		conn.Close()
		result.RetrySucceeded = true
	}

	return result, nil
}

// CheckFallback connects WITHOUT ECH to verify the server still works for
// non-ECH clients (inverse GREASE test).
func CheckFallback(host, port string, timeout time.Duration) (*FallbackResult, error) {
	conn, err := dialTLS(host, port, timeout, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return &FallbackResult{HandshakeSucceeded: false}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var domains []string
	for _, cert := range state.PeerCertificates {
		domains = append(domains, cert.DNSNames...)
	}
	return &FallbackResult{
		HandshakeSucceeded: true,
		CertDomains:        domains,
	}, nil
}

// CheckSNILeakage connects without ECH using the public_name as SNI and verifies
// the returned cert is for public_name, not the inner domain.
func CheckSNILeakage(publicName, port string, innerDomain string, timeout time.Duration) (leaks bool, certDomains []string, err error) {
	conn, err := dialTLS(publicName, port, timeout, &tls.Config{
		ServerName:         publicName,
		InsecureSkipVerify: true, // we're checking what cert is served, not validating trust
	})
	if err != nil {
		return false, nil, fmt.Errorf("connect to public_name %s: %w", publicName, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		certDomains = append(certDomains, cert.DNSNames...)
		// Check if any cert covers the inner domain — that would be a leak
		if err := cert.VerifyHostname(innerDomain); err == nil {
			return true, certDomains, nil
		}
	}
	return false, certDomains, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", v)
	}
}
