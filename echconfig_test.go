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

func TestParseECHConfigZeroCipherSuites(t *testing.T) {
	// contents: 1(id) + 2(kem) + 2(pklen) + 32(pk) + 2(cslen=0) + 1(maxname) + 1(pnlen) + 4(pn) + 2(extlen) = 47
	data := []byte{
		0x00, 0x33, // list length: 51
		0xfe, 0x0d, // version
		0x00, 0x2f, // config length: 47
		0x08,       // config_id
		0x00, 0x20, // kem_id: X25519
		0x00, 0x20, // public_key length: 32
		// 32 bytes of public key
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		// cipher_suites length: 0
		0x00, 0x00,
		// max_name_length
		0x00,
		// public_name length: 4
		0x04,
		// "test"
		0x74, 0x65, 0x73, 0x74,
		// extensions length: 0
		0x00, 0x00,
	}
	configs, err := ParseECHConfigList(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if len(configs[0].CipherSuites) != 0 {
		t.Errorf("expected 0 cipher suites, got %d", len(configs[0].CipherSuites))
	}
	if configs[0].PublicName != "test" {
		t.Errorf("public_name: got %q, want %q", configs[0].PublicName, "test")
	}
}

func TestParseECHConfigUnalignedCipherSuiteData(t *testing.T) {
	// contents: 1(id) + 2(kem) + 2(pklen) + 32(pk) + 2(cslen) + 5(csdata) + 1(maxname) + 1(pnlen) + 1(pn) + 2(extlen) = 49
	data := []byte{
		0x00, 0x35, // list length: 53
		0xfe, 0x0d, // version
		0x00, 0x31, // config length: 49
		0x08,       // config_id
		0x00, 0x20, // kem_id: X25519
		0x00, 0x20, // public_key length: 32
		// 32 bytes of public key
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		// cipher_suites length: 5
		0x00, 0x05,
		// one suite: HKDF-SHA256 + AES-128-GCM
		0x00, 0x01, 0x00, 0x01,
		// trailing byte
		0xab,
		// max_name_length
		0x00,
		// public_name length: 1
		0x01,
		// "x"
		0x78,
		// extensions length: 0
		0x00, 0x00,
	}
	_, err := ParseECHConfigList(data)
	if err == nil {
		t.Fatal("expected error for trailing bytes in cipher_suites, got nil")
	}
}

func TestParseECHConfigListTruncatedMidConfig(t *testing.T) {
	data := []byte{
		0x00, 0x20, // list length: 32 (claims more data than present)
		0xfe, 0x0d, // version
		0x00, 0x1c, // config length: 28 (but we truncate after a few bytes)
		0x08,       // config_id
		0x00, 0x20, // kem_id
		// truncated here — no public key data
	}
	_, err := ParseECHConfigList(data)
	if err == nil {
		t.Error("expected error for truncated ECHConfigList, got nil")
	}
}

func TestParseECHConfigNonUTF8PublicName(t *testing.T) {
	// The parser now rejects invalid UTF-8 in public_name.
	data := []byte{
		0x00, 0x33, // list length: 51
		0xfe, 0x0d, // version
		0x00, 0x2f, // config length: 47
		0x08,       // config_id
		0x00, 0x20, // kem_id: X25519
		0x00, 0x20, // public_key length: 32
		// 32 bytes of public key
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		// cipher_suites length: 0
		0x00, 0x00,
		// max_name_length
		0x00,
		// public_name length: 4
		0x04,
		// non-UTF-8 bytes: 0xff 0xfe 0x80 0x81
		0xff, 0xfe, 0x80, 0x81,
		// extensions length: 0
		0x00, 0x00,
	}
	_, err := ParseECHConfigList(data)
	if err == nil {
		t.Fatal("expected error for non-UTF-8 public_name, got nil")
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
