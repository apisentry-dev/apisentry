package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/apisentry-dev/apisentry/internal/scanner"
)

func makeScanResult() scanner.ScanResult {
	return scanner.ScanResult{
		Target:    "http://api.example.com",
		SpecFile:  "openapi.yaml",
		ScannedAt: time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC),
		Duration:  5 * time.Second,
		TotalTests: 100,
		Findings: []scanner.Finding{
			{
				Severity:    "CRITICAL",
				Category:    "Broken Auth (API2:2023)",
				Endpoint:    "http://api.example.com/api/orders",
				Method:      "GET",
				Description: "Auth bypass: GET /api/orders with NO auth token",
				Evidence:    "HTTP 200 — auth bypass succeeded",
				StatusCode:  200,
				Confidence:  85,
			},
			{
				Severity:    "HIGH",
				Category:    "BOLA (API1:2023)",
				Endpoint:    "http://api.example.com/api/users/1",
				Method:      "GET",
				Description: "BOLA: access GET /api/users/{userId} with unauthorized ID",
				Evidence:    "HTTP 200",
				StatusCode:  200,
				Confidence:  70,
			},
			{
				Severity:    "MEDIUM",
				Category:    "Unrestricted Resource Consumption (API4:2023)",
				Endpoint:    "http://api.example.com/api/login",
				Method:      "POST",
				Description: "No rate limiting on login endpoint",
				Evidence:    "20 requests sent, no HTTP 429 received",
				StatusCode:  200,
				Confidence:  80,
			},
		},
	}
}

func TestSummary(t *testing.T) {
	result := makeScanResult()
	s := summary(result.Findings)

	if s["CRITICAL"] != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", s["CRITICAL"])
	}
	if s["HIGH"] != 1 {
		t.Errorf("expected 1 HIGH, got %d", s["HIGH"])
	}
	if s["MEDIUM"] != 1 {
		t.Errorf("expected 1 MEDIUM, got %d", s["MEDIUM"])
	}
	if s["LOW"] != 0 {
		t.Errorf("expected 0 LOW, got %d", s["LOW"])
	}
}

func TestSummary_Empty(t *testing.T) {
	s := summary(nil)
	for sev, count := range s {
		if count != 0 {
			t.Errorf("expected 0 for %s in empty summary, got %d", sev, count)
		}
	}
}

func TestToJSON(t *testing.T) {
	result := makeScanResult()
	output, err := toJSON(result)
	if err != nil {
		t.Fatalf("toJSON returned error: %v", err)
	}

	var parsed jsonReport
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("toJSON output is not valid JSON: %v", err)
	}

	if parsed.Target != result.Target {
		t.Errorf("JSON target = %q, want %q", parsed.Target, result.Target)
	}
	if parsed.TotalTests != result.TotalTests {
		t.Errorf("JSON total_tests = %d, want %d", parsed.TotalTests, result.TotalTests)
	}
	if len(parsed.Findings) != 3 {
		t.Errorf("JSON findings count = %d, want 3", len(parsed.Findings))
	}
	if parsed.Summary["CRITICAL"] != 1 {
		t.Errorf("JSON summary CRITICAL = %d, want 1", parsed.Summary["CRITICAL"])
	}
}

func TestToSARIF(t *testing.T) {
	result := makeScanResult()
	output, err := toSARIF(result)
	if err != nil {
		t.Fatalf("toSARIF returned error: %v", err)
	}

	var parsed sarif
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("toSARIF output is not valid JSON: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(parsed.Runs))
	}
	if len(parsed.Runs[0].Results) != 3 {
		t.Errorf("expected 3 SARIF results, got %d", len(parsed.Runs[0].Results))
	}
	if parsed.Runs[0].Tool.Driver.Name != "APISentry" {
		t.Errorf("SARIF driver name = %q, want APISentry", parsed.Runs[0].Tool.Driver.Name)
	}
}

func TestSarifLevel(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"unknown", "note"},
	}
	for _, tc := range cases {
		got := sarifLevel(tc.severity)
		if got != tc.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestSarifRuleID(t *testing.T) {
	cases := []struct {
		category string
		want     string
	}{
		{"BOLA (API1:2023)", "OWASP-API1"},
		{"Broken Auth (API2:2023)", "OWASP-API2"},
		{"Mass Assignment (API3:2023)", "OWASP-API3"},
		{"Unrestricted Resource Consumption (API4:2023)", "OWASP-API4"},
		{"Broken Function Auth (API5:2023)", "OWASP-API5"},
		{"SSRF (API7:2023)", "OWASP-API7"},
	}
	for _, tc := range cases {
		got := sarifRuleID(tc.category)
		if got != tc.want {
			t.Errorf("sarifRuleID(%q) = %q, want %q", tc.category, got, tc.want)
		}
	}
}

func TestToText(t *testing.T) {
	result := makeScanResult()
	output := toText(result)

	if !strings.Contains(output, result.Target) {
		t.Error("text report missing target")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("text report missing CRITICAL severity")
	}
	if !strings.Contains(output, "HIGH") {
		t.Error("text report missing HIGH severity")
	}
	if !strings.Contains(output, "MEDIUM") {
		t.Error("text report missing MEDIUM severity")
	}
}

func TestToText_NoFindings(t *testing.T) {
	result := scanner.ScanResult{
		Target:     "http://secure-api.example.com",
		TotalTests: 50,
	}
	output := toText(result)

	if !strings.Contains(output, "TOTAL:    0") {
		t.Error("expected TOTAL: 0 in empty result text report")
	}
}

func TestToHTML(t *testing.T) {
	result := makeScanResult()
	output, err := toHTML(result)
	if err != nil {
		t.Fatalf("toHTML returned error: %v", err)
	}

	if !strings.Contains(output, "APISentry Security Report") {
		t.Error("HTML missing report title")
	}
	if !strings.Contains(output, result.Target) {
		t.Error("HTML missing target URL")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("HTML missing CRITICAL severity")
	}
}

func TestGenerate_ToFile(t *testing.T) {
	result := makeScanResult()
	tmpFile := t.TempDir() + "/report.json"

	if err := Generate(result, "json", tmpFile); err != nil {
		t.Fatalf("Generate to file returned error: %v", err)
	}
}
