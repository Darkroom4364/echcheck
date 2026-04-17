package main

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// ECHConfigInfo holds parsed, human-readable fields from a single ECHConfig.
type ECHConfigInfo struct {
	Version       uint16
	ConfigID      uint8
	KEMID         uint16
	KEM           string
	CipherSuites  []CipherSuiteInfo
	PublicKeyLen  int
	PublicName    string
	MaxNameLength uint8
	Raw           []byte
}

// CipherSuiteInfo holds a single KDF+AEAD pair.
type CipherSuiteInfo struct {
	KDFID  uint16
	KDF    string
	AEADID uint16
	AEAD   string
}

// ParseECHConfigList decodes a wire-format ECHConfigList into human-readable structs.
// Wire format: 2-byte total length || ECHConfig*
func ParseECHConfigList(data []byte) ([]ECHConfigInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ECHConfigList too short: %d bytes", len(data))
	}

	totalLen := int(binary.BigEndian.Uint16(data[:2]))
	rest := data[2:]
	if len(rest) < totalLen {
		return nil, fmt.Errorf("ECHConfigList length %d but only %d bytes remain", totalLen, len(rest))
	}
	rest = rest[:totalLen]

	var configs []ECHConfigInfo
	for len(rest) > 0 {
		cfg, n, err := parseOneECHConfig(rest)
		if err != nil {
			return configs, fmt.Errorf("parsing ECHConfig: %w", err)
		}
		configs = append(configs, cfg)
		rest = rest[n:]
	}
	return configs, nil
}

func parseOneECHConfig(data []byte) (ECHConfigInfo, int, error) {
	if len(data) < 4 {
		return ECHConfigInfo{}, 0, fmt.Errorf("ECHConfig too short for header")
	}

	version := binary.BigEndian.Uint16(data[0:2])
	configLen := int(binary.BigEndian.Uint16(data[2:4]))
	total := 4 + configLen
	if len(data) < total {
		return ECHConfigInfo{}, 0, fmt.Errorf("ECHConfig length %d but only %d bytes remain", configLen, len(data)-4)
	}

	cfg := ECHConfigInfo{
		Version: version,
		Raw:     data[:total],
	}

	if version != 0xfe0d {
		// Unknown version — skip but don't error (forward compat)
		return cfg, total, nil
	}

	contents := data[4:total]
	off := 0

	// HpkeKeyConfig
	if off >= len(contents) {
		return cfg, total, fmt.Errorf("truncated: no config_id")
	}
	cfg.ConfigID = contents[off]
	off++

	if off+2 > len(contents) {
		return cfg, total, fmt.Errorf("truncated: no kem_id")
	}
	cfg.KEMID = binary.BigEndian.Uint16(contents[off : off+2])
	cfg.KEM = kemName(cfg.KEMID)
	off += 2

	// public_key (length-prefixed, 2 bytes)
	if off+2 > len(contents) {
		return cfg, total, fmt.Errorf("truncated: no public_key length")
	}
	pkLen := int(binary.BigEndian.Uint16(contents[off : off+2]))
	off += 2
	if off+pkLen > len(contents) {
		return cfg, total, fmt.Errorf("truncated: public_key")
	}
	cfg.PublicKeyLen = pkLen
	off += pkLen

	// cipher_suites (length-prefixed, 2 bytes)
	if off+2 > len(contents) {
		return cfg, total, fmt.Errorf("truncated: no cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(contents[off : off+2]))
	off += 2
	if off+csLen > len(contents) {
		return cfg, total, fmt.Errorf("truncated: cipher_suites")
	}
	csData := contents[off : off+csLen]
	off += csLen

	for len(csData) >= 4 {
		kdfID := binary.BigEndian.Uint16(csData[0:2])
		aeadID := binary.BigEndian.Uint16(csData[2:4])
		cfg.CipherSuites = append(cfg.CipherSuites, CipherSuiteInfo{
			KDFID:  kdfID,
			KDF:    kdfName(kdfID),
			AEADID: aeadID,
			AEAD:   aeadName(aeadID),
		})
		csData = csData[4:]
	}
	if len(csData) != 0 {
		return cfg, total, fmt.Errorf("trailing bytes in cipher_suites")
	}

	// maximum_name_length (1 byte)
	if off >= len(contents) {
		return cfg, total, fmt.Errorf("truncated: no max_name_length")
	}
	cfg.MaxNameLength = contents[off]
	off++

	// public_name (length-prefixed, 1 byte)
	if off >= len(contents) {
		return cfg, total, fmt.Errorf("truncated: no public_name length")
	}
	pnLen := int(contents[off])
	off++
	if off+pnLen > len(contents) {
		return cfg, total, fmt.Errorf("truncated: public_name")
	}
	pnBytes := contents[off : off+pnLen]
	if !utf8.Valid(pnBytes) {
		return cfg, total, fmt.Errorf("invalid UTF-8 in public_name")
	}
	cfg.PublicName = string(pnBytes)

	return cfg, total, nil
}

func kemName(id uint16) string {
	switch id {
	case 0x0010:
		return "DHKEM(P-256)"
	case 0x0011:
		return "DHKEM(P-384)"
	case 0x0012:
		return "DHKEM(P-521)"
	case 0x0020:
		return "DHKEM(X25519)"
	case 0x0021:
		return "DHKEM(X448)"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", id)
	}
}

func kdfName(id uint16) string {
	switch id {
	case 0x0001:
		return "HKDF-SHA256"
	case 0x0002:
		return "HKDF-SHA384"
	case 0x0003:
		return "HKDF-SHA512"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", id)
	}
}

func aeadName(id uint16) string {
	switch id {
	case 0x0001:
		return "AES-128-GCM"
	case 0x0002:
		return "AES-256-GCM"
	case 0x0003:
		return "ChaCha20Poly1305"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", id)
	}
}
