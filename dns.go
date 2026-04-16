package main

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// QueryHTTPSRecord queries the DNS HTTPS record for a domain and extracts
// the raw ECHConfigList bytes from the ech SvcParam.
func QueryHTTPSRecord(domain, resolver string) (echConfigList []byte, ttl uint32, err error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.RecursionDesired = true

	r, err := dns.Exchange(m, resolver)
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
