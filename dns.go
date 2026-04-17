package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

// DNSOptions holds DNS resolution configuration.
type DNSOptions struct {
	Resolver string // UDP resolver address (e.g. "1.1.1.1:53")
	DoHURL   string // DNS-over-HTTPS endpoint (e.g. "https://1.1.1.1/dns-query")
}

// exchange sends a DNS query using DoH if configured, otherwise UDP.
func (o DNSOptions) exchange(m *dns.Msg) (*dns.Msg, error) {
	if o.DoHURL != "" {
		return dohExchange(o.DoHURL, m)
	}
	return dns.Exchange(m, o.Resolver)
}

// dohExchange sends a DNS message over HTTPS (RFC 8484).
func dohExchange(url string, m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns message: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("creating doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading doh response: %w", err)
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking doh response: %w", err)
	}
	return r, nil
}

// QueryHTTPSRecord queries the DNS HTTPS record for a domain and extracts
// the raw ECHConfigList bytes from the ech SvcParam.
func QueryHTTPSRecord(domain string, opts DNSOptions) (echConfigList []byte, ttl uint32, err error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.RecursionDesired = true

	r, err := opts.exchange(m)
	if err != nil {
		return nil, 0, fmt.Errorf("dns query failed: %w", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("dns query returned %s", dns.RcodeToString[r.Rcode])
	}

	for _, ans := range r.Answer {
		https, ok := ans.(*dns.HTTPS)
		if !ok {
			continue
		}
		ttl = ans.Header().Ttl
		for _, svcb := range https.Value {
			if svcb.Key() == dns.SVCB_ECHCONFIG {
				ech, ok := svcb.(*dns.SVCBECHConfig)
				if ok && len(ech.ECH) > 0 {
					return ech.ECH, ttl, nil
				}
			}
		}
	}

	return nil, 0, nil // no HTTPS record or no ech param — not an error
}

// ResolveAddr resolves a domain to an IP address for TLS dialing.
func ResolveAddr(domain, resolver string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	r, err := dns.Exchange(m, resolver)
	if err != nil {
		return "", fmt.Errorf("dns A query failed: %w", err)
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	// Try AAAA
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	r, err = dns.Exchange(m, resolver)
	if err != nil {
		return "", fmt.Errorf("dns AAAA query failed: %w", err)
	}
	for _, ans := range r.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			return aaaa.AAAA.String(), nil
		}
	}

	// Fallback to system resolver
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return "", fmt.Errorf("could not resolve %s: %w", domain, err)
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("no addresses found for %s", domain)
}
