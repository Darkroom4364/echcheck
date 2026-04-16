package main

import (
	"testing"
)

// Real ECHConfigList captured from crypto.cloudflare.com (may go stale over time,
// but the wire format is stable for unit testing the parser).
var sampleECHConfigList = []byte{
	// 2-byte length prefix
	0x00, 0x45,
	// ECHConfig: version 0xfe0d
	0xfe, 0x0d,
	// 2-byte config length
	0x00, 0x41,
	// config_id
	0x08,
	// kem_id: X25519 (0x0020)
	0x00, 0x20,
	// public_key length (2 bytes): 32
	0x00, 0x20,
	// 32 bytes of public key (dummy)
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	// cipher_suites length (2 bytes): 4 (one suite)
	0x00, 0x04,
	// kdf_id: HKDF-SHA256 (0x0001)
	0x00, 0x01,
	// aead_id: AES-128-GCM (0x0001)
	0x00, 0x01,
	// maximum_name_length
	0x00,
	// public_name length (1 byte): 18
	0x12,
	// "cloudflare-ech.com"
	0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61,
	0x72, 0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63,
	0x6f, 0x6d,
	// extensions length (2 bytes): 0
	0x00, 0x00,
}

func TestParseECHConfigList(t *testing.T) {
	configs, err := ParseECHConfigList(sampleECHConfigList)
	if err != nil {
		t.Fatalf("ParseECHConfigList: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}

	cfg := configs[0]
	if cfg.Version != 0xfe0d {
		t.Errorf("version: got 0x%04x, want 0xfe0d", cfg.Version)
	}
	if cfg.ConfigID != 0x08 {
		t.Errorf("config_id: got 0x%02x, want 0x08", cfg.ConfigID)
	}
	if cfg.KEMID != 0x0020 {
		t.Errorf("kem_id: got 0x%04x, want 0x0020", cfg.KEMID)
	}
	if cfg.KEM != "DHKEM(X25519)" {
		t.Errorf("kem: got %q, want DHKEM(X25519)", cfg.KEM)
	}
	if cfg.PublicKeyLen != 32 {
		t.Errorf("public_key_len: got %d, want 32", cfg.PublicKeyLen)
	}
	if len(cfg.CipherSuites) != 1 {
		t.Fatalf("cipher_suites: got %d, want 1", len(cfg.CipherSuites))
	}
	if cfg.CipherSuites[0].KDF != "HKDF-SHA256" {
		t.Errorf("kdf: got %q, want HKDF-SHA256", cfg.CipherSuites[0].KDF)
	}
	if cfg.CipherSuites[0].AEAD != "AES-128-GCM" {
		t.Errorf("aead: got %q, want AES-128-GCM", cfg.CipherSuites[0].AEAD)
	}
	if cfg.PublicName != "cloudflare-ech.com" {
		t.Errorf("public_name: got %q, want cloudflare-ech.com", cfg.PublicName)
	}
	if cfg.MaxNameLength != 0 {
		t.Errorf("max_name_length: got %d, want 0", cfg.MaxNameLength)
	}
}

func TestParseECHConfigListTooShort(t *testing.T) {
	_, err := ParseECHConfigList([]byte{0x00})
	if err == nil {
		t.Error("expected error for 1-byte input")
	}
}

func TestParseECHConfigListEmpty(t *testing.T) {
	// Valid list with 0 length
	configs, err := ParseECHConfigList([]byte{0x00, 0x00})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("expected 0 configs, got %d", len(configs))
	}
}

func TestParseECHConfigListUnknownVersion(t *testing.T) {
	data := []byte{
		0x00, 0x06, // list length: 6
		0xff, 0xff, // version: unknown
		0x00, 0x02, // config length: 2
		0xde, 0xad, // opaque contents
	}
	configs, err := ParseECHConfigList(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs[0].Version != 0xffff {
		t.Errorf("version: got 0x%04x, want 0xffff", configs[0].Version)
	}
}
