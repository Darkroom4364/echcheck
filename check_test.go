package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// mockConn implements tlsConn for testing.
type mockConn struct {
	state tls.ConnectionState
}

func (m *mockConn) ConnectionState() tls.ConnectionState { return m.state }
func (m *mockConn) Close() error                         { return nil }

// withMockDial replaces dialTLS for the duration of a test and restores it after.
// Note: not safe with t.Parallel() since dialTLS is a package-level var.
func withMockDial(t *testing.T, fn func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error)) {
	t.Helper()
	orig := dialTLS
	dialTLS = fn
	t.Cleanup(func() { dialTLS = orig })
}

// --- parseTarget ---

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"[::1]:443", "::1", "443"},
	}
	for _, tt := range tests {
		host, port := parseTarget(tt.input)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("parseTarget(%q) = (%q, %q), want (%q, %q)", tt.input, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

// --- CheckECHNegotiation ---

func TestCheckECHNegotiation_Accepted(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return &mockConn{state: tls.ConnectionState{
			Version:     tls.VersionTLS13,
			CipherSuite: tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{
				{DNSNames: []string{"example.com"}},
			},
		}}, nil
	})

	result, err := CheckECHNegotiation("example.com", "443", []byte{}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Accepted {
		t.Error("expected Accepted=true")
	}
	if !result.TLS13 {
		t.Error("expected TLS13=true")
	}
}

func TestCheckECHNegotiation_Rejected(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return nil, &tls.ECHRejectionError{}
	})

	result, err := CheckECHNegotiation("example.com", "443", []byte{}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Accepted {
		t.Error("expected Accepted=false")
	}
}

func TestCheckECHNegotiation_DialError(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return nil, errors.New("connection refused")
	})

	_, err := CheckECHNegotiation("example.com", "443", []byte{}, 5*time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- CheckRetryConfigs ---

func TestCheckRetryConfigs_ValidRetry(t *testing.T) {
	callCount := 0
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		callCount++
		if callCount == 1 {
			// First call (corrupted config) → rejection with retry configs
			return nil, &tls.ECHRejectionError{RetryConfigList: sampleECHConfigList}
		}
		// Second call (retry) → success
		return &mockConn{}, nil
	})

	result, err := CheckRetryConfigs("example.com", "443", sampleECHConfigList, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.RetryConfigsReceived {
		t.Error("expected RetryConfigsReceived=true")
	}
	if !result.RetryConfigsValid {
		t.Error("expected RetryConfigsValid=true")
	}
	if !result.RetrySucceeded {
		t.Error("expected RetrySucceeded=true")
	}
}

func TestCheckRetryConfigs_NoRetryConfigs(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return nil, &tls.ECHRejectionError{RetryConfigList: nil}
	})

	result, err := CheckRetryConfigs("example.com", "443", sampleECHConfigList, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RetryConfigsReceived {
		t.Error("expected RetryConfigsReceived=false")
	}
}

func TestCheckRetryConfigs_ParseError(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		// Return invalid bytes as retry config list
		return nil, &tls.ECHRejectionError{RetryConfigList: []byte{0xff}}
	})

	result, err := CheckRetryConfigs("example.com", "443", sampleECHConfigList, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ParseError == nil {
		t.Error("expected ParseError to be set")
	}
	if !result.RetryConfigsReceived {
		t.Error("expected RetryConfigsReceived=true")
	}
}

func TestCheckRetryConfigs_RetryFails(t *testing.T) {
	callCount := 0
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		callCount++
		if callCount == 1 {
			return nil, &tls.ECHRejectionError{RetryConfigList: sampleECHConfigList}
		}
		return nil, errors.New("retry failed")
	})

	result, err := CheckRetryConfigs("example.com", "443", sampleECHConfigList, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RetrySucceeded {
		t.Error("expected RetrySucceeded=false")
	}
	if result.RetryError == nil {
		t.Error("expected RetryError to be set")
	}
}

func TestCheckRetryConfigs_AcceptedCorrupted(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		// Server unexpectedly accepted corrupted config
		return &mockConn{}, nil
	})

	result, err := CheckRetryConfigs("example.com", "443", sampleECHConfigList, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RetryConfigsReceived {
		t.Error("expected RetryConfigsReceived=false when server accepted corrupted config")
	}
}

// --- CheckFallback ---

func TestCheckFallback_Success(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return &mockConn{state: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{DNSNames: []string{"example.com", "www.example.com"}},
			},
		}}, nil
	})

	result, err := CheckFallback("example.com", "443", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HandshakeSucceeded {
		t.Error("expected HandshakeSucceeded=true")
	}
	if len(result.CertDomains) != 2 {
		t.Errorf("expected 2 cert domains, got %d", len(result.CertDomains))
	}
}

func TestCheckFallback_Failure(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return nil, errors.New("handshake failed")
	})

	result, err := CheckFallback("example.com", "443", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HandshakeSucceeded {
		t.Error("expected HandshakeSucceeded=false")
	}
	if result.ErrorDetail == "" {
		t.Error("expected ErrorDetail to be set")
	}
}

// --- CheckSNILeakage ---

func TestCheckSNILeakage_NoLeak(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return &mockConn{state: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{DNSNames: []string{"public.example.com"}},
			},
		}}, nil
	})

	leaks, domains, err := CheckSNILeakage("public.example.com", "443", "secret.example.com", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if leaks {
		t.Error("expected no leak")
	}
	if len(domains) != 1 {
		t.Errorf("expected 1 domain, got %d", len(domains))
	}
}

func TestCheckSNILeakage_Leak(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return &mockConn{state: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{DNSNames: []string{"secret.example.com", "public.example.com"}},
			},
		}}, nil
	})

	leaks, _, err := CheckSNILeakage("public.example.com", "443", "secret.example.com", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !leaks {
		t.Error("expected leak")
	}
}

func TestCheckSNILeakage_ConnError(t *testing.T) {
	withMockDial(t, func(host, port string, timeout time.Duration, cfg *tls.Config) (tlsConn, error) {
		return nil, errors.New("connection failed")
	})

	_, _, err := CheckSNILeakage("public.example.com", "443", "secret.example.com", 5*time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
}
