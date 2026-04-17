# echcheck

Test and validate Encrypted Client Hello (ECH) deployment. The first dedicated ECH compliance scanner — built on Go 1.24's native ECH support.

## Why

ECH (RFC 9849, finalized March 2026) encrypts the TLS ClientHello, hiding which site you're visiting from network observers. It's the biggest TLS privacy upgrade since TLS 1.3. Cloudflare, Chrome, Firefox, and Safari all support it. OpenSSL 4.0 shipped ECH support on April 14, 2026 — server adoption is about to accelerate.

No dedicated testing tool exists. testssl.sh hasn't implemented ECH checks. SSL Labs does passive DNS lookups only. `echcheck` performs active ECH negotiation, retry validation, GREASE handling, and SNI leakage detection.

## What It Checks

| Check | What it does |
|---|---|
| **DNS HTTPS Record** | Queries HTTPS RR, extracts and parses ECHConfigList from the `ech` SvcParam |
| **ECHConfig Validation** | Validates version (0xfe0d), KEM, KDF, AEAD, public key, public_name, max_name_length |
| **ECH Negotiation** | Attempts a real TLS 1.3 connection with ECH and verifies server acceptance |
| **Retry Configs** | Triggers a retry scenario (bad config_id), validates server returns well-formed retry_configs |
| **GREASE Handling** | Sends GREASE ECH extension, verifies server ignores it gracefully |
| **SNI Leakage** | Verifies the real server name never appears in cleartext — outer SNI must equal public_name |
| **Certificate Validation** | Inner cert valid for target domain, outer cert valid for public_name |

## Output

```
$ echcheck example.com

  ECH Check Results for example.com
  ──────────────────────────────────

  DNS HTTPS Record        ✓  Found (TTL: 300s)
  ECHConfig Version       ✓  0xfe0d (RFC 9849)
  KEM                     ✓  X25519 (0x0020)
  KDF / AEAD              ✓  HKDF-SHA256 / AES-128-GCM
  Public Name             ✓  cloudflare-ech.com
  Config ID               ✓  0x42
  Max Name Length          ✓  128 (adequate)

  ECH Negotiation         ✓  Accepted (TLS 1.3)
  Retry Configs           ✓  Server returns valid retry_configs
  GREASE Handling         ✓  Server ignores GREASE gracefully
  SNI Leakage             ✓  Outer SNI = public_name (no leak)
  Certificate (inner)     ✓  Valid for example.com
  Certificate (outer)     ✓  Valid for cloudflare-ech.com

  Overall: PASS (12/12 checks)
```

### No ECH

```
$ echcheck legacy-server.com

  ECH Check Results for legacy-server.com
  ────────────────────────────────────────

  DNS HTTPS Record        ✗  No HTTPS RR found
  ECH Negotiation         —  Skipped (no ECHConfig)

  Overall: NO ECH SUPPORT
```

## Installation

```bash
# Go
go install github.com/Darkroom4364/echcheck@latest

# Homebrew
brew install darkroom4364/tap/echcheck

# Binary
curl -sSL https://github.com/Darkroom4364/echcheck/releases/latest/download/echcheck-$(uname -s)-$(uname -m) -o echcheck
chmod +x echcheck
```

Requires Go 1.24+ (uses `crypto/tls` native ECH support). Single binary, zero runtime dependencies.

## Usage

```bash
# Check a single domain
echcheck example.com

# JSON output for CI/CD
echcheck --json example.com

# Batch scan from stdin
cat domains.txt | echcheck --batch

# Custom DNS resolver
echcheck --resolver 1.1.1.1:53 example.com

# Use DNS-over-HTTPS for record lookup (detect HTTPS record stripping)
echcheck --doh https://1.1.1.1/dns-query example.com

# Verbose — show full handshake details
echcheck -v example.com

# Check specific port
echcheck example.com:8443
```

## How ECH Works

```
                          Passive Observer
                          sees only: ──────────────┐
                                                    │
Client ──────────────────────────────────────── Server
         ClientHelloOuter                          │
         ├── SNI: cloudflare-ech.com  ◄────────────┘  (cover name)
         └── encrypted_client_hello:
             └── ClientHelloInner (encrypted)
                 └── SNI: real-site.com   ← hidden from observer
```

1. Client fetches the server's ECH public key from DNS (HTTPS record)
2. Client encrypts the real ClientHello (inner) with HPKE
3. Client sends a cover ClientHello (outer) with the CDN's public_name as SNI
4. Server decrypts the inner ClientHello and completes the handshake
5. Passive observers only see the cover name, never the real destination

## Technical Details

- **Protocol:** RFC 9849 (Encrypted Client Hello), built on HPKE (RFC 9180)
- **DNS:** HTTPS resource records (RFC 9460) carry ECHConfig in the `ech` SvcParam
- **Modes:** Shared-mode (single server) and split-mode (frontend proxy + backend)
- **Fallback:** On failure, server returns retry_configs with fresh keys; client retries once, then falls back to non-ECH

## Implementation

Built on Go stdlib — no external TLS libraries:

- `crypto/tls` — ECH client support via `Config.EncryptedClientHelloConfigList` (Go 1.23+), rejection handling via `*tls.ECHRejectionError` with `RetryConfigList`
- `github.com/miekg/dns` — HTTPS/SVCB record queries with `dns.SVCBECHConfig` parsing

## Positioning

| Tool | Active ECH Test | Retry Validation | GREASE Test | SNI Leak Check | Batch Mode | CLI |
|---|---|---|---|---|---|---|
| **echcheck** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| testssl.sh | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| SSL Labs | ✗ | ✗ | ✗ | ✗ | ✗ | Web |
| curl --ech | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ |

## License

Apache 2.0
