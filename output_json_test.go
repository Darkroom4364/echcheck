package main

import (
	"encoding/json"
	"testing"
)

func TestReportJSONRoundtrip(t *testing.T) {
	r := &Report{Domain: "example.com", ECHSupported: true}
	r.Add("DNS HTTPS Record", StatusPass, "Found (TTL: 300s)")
	r.Add("ECH Negotiation", StatusFail, "Rejected by server")
	r.Add("SNI Leakage", StatusSkip, "public_name same as domain")
	r.Finalize()

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Domain != "example.com" {
		t.Errorf("domain: got %q, want %q", decoded.Domain, "example.com")
	}
	if len(decoded.Checks) != 3 {
		t.Fatalf("checks: got %d, want 3", len(decoded.Checks))
	}
	if decoded.Checks[0].Status != "pass" {
		t.Errorf("check[0] status: got %q, want %q", decoded.Checks[0].Status, "pass")
	}
	if decoded.Checks[1].Status != "fail" {
		t.Errorf("check[1] status: got %q, want %q", decoded.Checks[1].Status, "fail")
	}
	if decoded.Checks[2].Status != "skip" {
		t.Errorf("check[2] status: got %q, want %q", decoded.Checks[2].Status, "skip")
	}
	if decoded.Summary.Total != 2 {
		t.Errorf("total: got %d, want 2", decoded.Summary.Total)
	}
	if decoded.Summary.Passed != 1 {
		t.Errorf("passed: got %d, want 1", decoded.Summary.Passed)
	}
	if decoded.Summary.Failed != 1 {
		t.Errorf("failed: got %d, want 1", decoded.Summary.Failed)
	}
}

func TestReportWarnCountsInTotal(t *testing.T) {
	r := &Report{ECHSupported: true}
	r.Add("check1", StatusPass, "ok")
	r.Add("check2", StatusWarn, "warning")
	r.Finalize()

	if r.Summary.Total != 2 {
		t.Errorf("total: got %d, want 2", r.Summary.Total)
	}
	// Warnings count toward total but not passed or failed
	if r.Summary.Passed != 1 {
		t.Errorf("passed: got %d, want 1", r.Summary.Passed)
	}
	if r.Summary.Failed != 0 {
		t.Errorf("failed: got %d, want 0", r.Summary.Failed)
	}
}
