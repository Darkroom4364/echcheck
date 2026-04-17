package main

import "testing"

func TestExitCodeAllPass(t *testing.T) {
	r := &Report{ECHSupported: true}
	r.Add("check1", StatusPass, "ok")
	r.Add("check2", StatusPass, "ok")
	r.Finalize()
	if got := r.ExitCode(); got != 0 {
		t.Errorf("ExitCode() = %d, want 0", got)
	}
}

func TestExitCodeAnyFail(t *testing.T) {
	r := &Report{ECHSupported: true}
	r.Add("check1", StatusPass, "ok")
	r.Add("check2", StatusFail, "bad")
	r.Finalize()
	if got := r.ExitCode(); got != 1 {
		t.Errorf("ExitCode() = %d, want 1", got)
	}
}

func TestExitCodeNoECHSupport(t *testing.T) {
	r := &Report{ECHSupported: false}
	r.Add("dns", StatusFail, "no HTTPS record")
	r.Finalize()
	if got := r.ExitCode(); got != 2 {
		t.Errorf("ExitCode() = %d, want 2", got)
	}
}

func TestSkippedChecksDontInflateTotal(t *testing.T) {
	r := &Report{ECHSupported: true}
	r.Add("check1", StatusPass, "ok")
	r.Add("check2", StatusSkip, "skipped")
	r.Add("check3", StatusPass, "ok")
	r.Finalize()

	// Skipped checks are excluded from Total
	if r.Summary.Total != 2 {
		t.Errorf("Total = %d, want 2", r.Summary.Total)
	}
	if r.Summary.Passed != 2 {
		t.Errorf("Passed = %d, want 2", r.Summary.Passed)
	}
	if r.Summary.Failed != 0 {
		t.Errorf("Failed = %d, want 0", r.Summary.Failed)
	}
}

// NO_COLOR env var is not implemented in output.go.
// The code uses raw ANSI constants unconditionally.
// Skipping NO_COLOR test since there is no such logic to verify.
