package main

import (
	"os"
	"testing"
	"time"
)

func skipUnlessLive(t *testing.T) {
	if os.Getenv("ECHCHECK_LIVE") == "" {
		t.Skip("skipping live test (set ECHCHECK_LIVE=1 to enable)")
	}
}

func TestLiveECHNegotiation(t *testing.T) {
	skipUnlessLive(t)

	echConfigList, _, err := QueryHTTPSRecord("crypto.cloudflare.com", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("DNS query: %v", err)
	}
	if echConfigList == nil {
		t.Fatal("no ECHConfig in DNS for crypto.cloudflare.com")
	}

	result, err := CheckECHNegotiation("crypto.cloudflare.com", "443", echConfigList, 10*time.Second)
	if err != nil {
		t.Fatalf("negotiation: %v", err)
	}
	if !result.Accepted {
		t.Error("ECH negotiation was not accepted")
	}
	if result.TLSVersion != "TLS 1.3" {
		t.Errorf("TLS version: got %q, want TLS 1.3", result.TLSVersion)
	}
}

func TestLiveRetryConfigs(t *testing.T) {
	skipUnlessLive(t)

	echConfigList, _, err := QueryHTTPSRecord("crypto.cloudflare.com", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("DNS query: %v", err)
	}
	if echConfigList == nil {
		t.Fatal("no ECHConfig in DNS")
	}

	result, err := CheckRetryConfigs("crypto.cloudflare.com", "443", echConfigList, 10*time.Second)
	if err != nil {
		t.Fatalf("retry configs: %v", err)
	}
	if !result.RetryConfigsReceived {
		t.Error("server did not send retry_configs")
	}
	if !result.RetryConfigsValid {
		t.Error("retry_configs are not valid")
	}
	if !result.RetrySucceeded {
		t.Error("retry with new configs did not succeed")
	}
}

func TestLiveFallback(t *testing.T) {
	skipUnlessLive(t)

	result, err := CheckFallback("crypto.cloudflare.com", "443", 10*time.Second)
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if !result.HandshakeSucceeded {
		t.Error("non-ECH handshake failed")
	}
}

func TestLiveNoECH(t *testing.T) {
	skipUnlessLive(t)

	echConfigList, _, err := QueryHTTPSRecord("example.com", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("DNS query: %v", err)
	}
	if echConfigList != nil {
		t.Error("expected no ECHConfig for example.com")
	}
}
