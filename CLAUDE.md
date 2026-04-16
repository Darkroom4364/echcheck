# echcheck — ECH Compliance Scanner

## What This Is

A Go CLI tool that tests Encrypted Client Hello (ECH) deployment on servers. RFC 9849 was finalized March 2026, OpenSSL 4.0 shipped ECH support April 14 2026, and no dedicated testing tool exists (testssl.sh hasn't implemented it, SSL Labs does passive DNS only).

## Technical Context

### ECH in a Nutshell
ECH encrypts the TLS ClientHello SNI field using HPKE. The server's ECH public key is published in DNS via HTTPS resource records. The client sends an outer ClientHello (with a cover SNI called `public_name`) and an encrypted inner ClientHello (with the real SNI). Passive observers only see the cover name.

### Key API Details (Go 1.24+)

**ECH negotiation:**
```go
conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
    ServerName:                     domain,
    EncryptedClientHelloConfigList: echConfigListBytes, // raw bytes from DNS
})
// err == nil → ECH accepted
// err is *tls.ECHRejectionError → rejected, .RetryConfigList has fresh keys
```

**DNS HTTPS record (miekg/dns):**
```go
m := new(dns.Msg)
m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
r, err := dns.Exchange(m, "1.1.1.1:53")
// parse r.Answer for *dns.HTTPS, find SVCBECHConfig in .Value
// SVCBECHConfig.ECH is []byte containing the raw ECHConfigList
```

### ECHConfigList Wire Format (RFC 9849 §4)
```
ECHConfigList := 2-byte total length || ECHConfig*

ECHConfig := 2-byte version (0xfe0d) || 2-byte length || contents

contents := HpkeKeyConfig || 1-byte max_name_length || public_name (length-prefixed) || extensions (length-prefixed)

HpkeKeyConfig := 1-byte config_id || 2-byte kem_id || public_key (length-prefixed) || cipher_suites (length-prefixed)

cipher_suite := 2-byte kdf_id || 2-byte aead_id
```

**Important:** The ECHConfigList starts with a 2-byte overall length prefix before the individual configs. Consume this first.

### SNI Leakage Check — Correct Flow
On ECH rejection, Go returns `tls.ECHRejectionError` before the handshake completes — you can't inspect certs from a rejected attempt. To check SNI leakage: connect WITHOUT ECH to the server using the public_name as SNI, verify the cert is for public_name (not the inner domain).

### GREASE Test — v1 Approach
Go's `crypto/tls` validates ECHConfigList before sending, so you can't inject random GREASE bytes. For v1: do an "inverse GREASE" test — connect without ECH, verify the server still completes the handshake normally (proves it doesn't require ECH).

## Competition
- **Zero dedicated ECH testing tools exist** with meaningful adoption
- testssl.sh: issue #1641 open since 2020, not implemented
- SSL Labs: passive DNS check only, no active ECH negotiation
- curl --ech: works but no retry validation, no SNI leak check, no structured output

## Implementation Plan

See `~/.claude/plans/sequential-fluttering-moth.md` for the full approved plan. Summary:

### Structure
```
echcheck/
├── main.go          # CLI flags (stdlib flag), orchestration
├── dns.go           # DNS HTTPS record query + ECHConfig extraction
├── echconfig.go     # ECHConfigList wire-format parsing → human-readable
├── ech.go           # ECH negotiation, retry, GREASE, SNI leakage checks
├── output.go        # Terminal (colored) + JSON output formatting
├── echconfig_test.go # Unit tests (ECHConfig parsing, always run)
├── ech_test.go      # Live integration tests (gated behind ECHCHECK_LIVE=1)
└── .github/workflows/ci.yml
```

### Dependencies
- `github.com/miekg/dns` — HTTPS/SVCB record queries
- Go stdlib for everything else. No color library (raw ANSI codes).

### Checks (in order)
1. DNS HTTPS record presence + TTL
2. ECHConfig parsing + validation (version, KEM, KDF, AEAD, public_name, max_name_length)
3. ECH negotiation (active TLS connect with ECH)
4. Retry configs (connect with corrupted config, verify server sends valid retry_configs)
5. Non-ECH fallback / inverse GREASE (connect without ECH, verify handshake succeeds)
6. SNI leakage (connect without ECH to public_name, verify cert is for public_name not inner domain)
7. Certificate validation (with ECH: cert valid for inner domain)

### CLI Flags
```
echcheck <domain[:port]>
  --json           JSON output for CI/CD
  --resolver       Custom DNS resolver (default: 1.1.1.1:53)
  --timeout        Connection timeout (default: 10s)
  --verbose / -v   Show raw ECHConfig hex, cert chains, handshake details
```

### Exit Codes
- 0: all checks pass
- 1: any check failed
- 2: no ECH support (no HTTPS record / no ech param)

### Deferred to v2
- `--doh` (DNS-over-HTTPS) — adds HTTP/2 complexity
- `--batch` — `xargs` covers it
- Raw GREASE ECH injection via crafted ClientHello

### Test Targets
- `crypto.cloudflare.com` — Cloudflare's ECH test endpoint
- `defo.ie` — DEfO project's ECH test server
- `example.com` — no ECH support (negative test)

## Build & Test
```bash
go build && ./echcheck crypto.cloudflare.com        # should PASS
./echcheck example.com                               # should show NO ECH SUPPORT
./echcheck --json crypto.cloudflare.com | jq .       # structured output
go test -v                                           # unit tests
ECHCHECK_LIVE=1 go test -v                           # live integration tests
```
