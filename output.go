package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ANSI color helpers
var (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorDim    = "\033[2m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		colorReset = ""
		colorGreen = ""
		colorRed = ""
		colorYellow = ""
		colorDim = ""
	}
}

// CheckStatus represents the outcome of a single check.
type CheckStatus int

const (
	StatusPass CheckStatus = iota
	StatusFail
	StatusWarn
	StatusSkip
)

// CheckResult holds one check's outcome for output.
type CheckResult struct {
	Name   string      `json:"name"`
	Status string      `json:"status"`
	Detail string      `json:"detail"`
	check  CheckStatus // internal, not serialized
}

// Report holds the full output for a domain.
type Report struct {
	Domain       string        `json:"domain"`
	ECHSupported bool          `json:"ech_supported"`
	Checks       []CheckResult `json:"checks"`
	Summary      struct {
		Passed int `json:"passed"`
		Failed int `json:"failed"`
		Total  int `json:"total"`
	} `json:"summary"`
}

func (r *Report) Add(name string, status CheckStatus, detail string) {
	statusStr := "pass"
	switch status {
	case StatusFail:
		statusStr = "fail"
	case StatusWarn:
		statusStr = "warn"
	case StatusSkip:
		statusStr = "skip"
	}
	r.Checks = append(r.Checks, CheckResult{
		Name:   name,
		Status: statusStr,
		Detail: detail,
		check:  status,
	})
}

func (r *Report) Finalize() {
	for _, c := range r.Checks {
		if c.check == StatusSkip {
			continue
		}
		r.Summary.Total++
		switch c.check {
		case StatusPass:
			r.Summary.Passed++
		case StatusFail:
			r.Summary.Failed++
		}
	}
}

// ExitCode returns the appropriate exit code based on the report.
func (r *Report) ExitCode() int {
	if !r.ECHSupported {
		return 2
	}
	if r.Summary.Failed > 0 {
		return 1
	}
	return 0
}

// PrintJSON outputs the report as JSON.
func (r *Report) PrintJSON() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
	}
}

// PrintText outputs the report as formatted terminal text.
func (r *Report) PrintText() {
	header := fmt.Sprintf("ECH Check Results for %s", r.Domain)
	line := strings.Repeat("─", len(header))
	fmt.Printf("\n  %s\n  %s\n\n", header, line)

	if !r.ECHSupported {
		for _, c := range r.Checks {
			printCheck(c)
		}
		fmt.Printf("\n  Overall: %sNO ECH SUPPORT%s\n\n", colorYellow, colorReset)
		return
	}

	for _, c := range r.Checks {
		printCheck(c)
	}

	color := colorGreen
	label := "PASS"
	if r.Summary.Failed > 0 {
		color = colorRed
		label = "FAIL"
	}
	fmt.Printf("\n  Overall: %s%s%s (%d/%d checks)\n\n",
		color, label, colorReset, r.Summary.Passed, r.Summary.Total)
}

func printCheck(c CheckResult) {
	var icon, color string
	switch c.check {
	case StatusPass:
		icon, color = "✓", colorGreen
	case StatusFail:
		icon, color = "✗", colorRed
	case StatusWarn:
		icon, color = "⚠", colorYellow
	case StatusSkip:
		icon, color = "—", colorDim
	}
	fmt.Printf("  %-24s %s%s%s  %s\n", c.Name, color, icon, colorReset, c.Detail)
}
