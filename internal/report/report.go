package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/apisentry-dev/apisentry/internal/scanner"
)

// Generate writes a report to outFile in the given format ("json", "html", "sarif", "text")
func Generate(result scanner.ScanResult, format, outFile string) error {
	var content string
	var err error

	switch strings.ToLower(format) {
	case "json":
		content, err = toJSON(result)
	case "html":
		content, err = toHTML(result)
	case "sarif":
		content, err = toSARIF(result)
	default:
		content = toText(result)
	}

	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	if outFile == "" {
		fmt.Print(content)
		return nil
	}

	return os.WriteFile(outFile, []byte(content), 0644)
}

// ── JSON ──────────────────────────────────────────────────────────────────────

type jsonReport struct {
	ScannedAt  time.Time         `json:"scanned_at"`
	Target     string            `json:"target"`
	SpecFile   string            `json:"spec_file"`
	Duration   string            `json:"duration"`
	TotalTests int               `json:"total_tests"`
	Summary    map[string]int    `json:"summary"`
	Findings   []scanner.Finding `json:"findings"`
}

func toJSON(r scanner.ScanResult) (string, error) {
	rep := jsonReport{
		ScannedAt:  r.ScannedAt,
		Target:     r.Target,
		SpecFile:   r.SpecFile,
		Duration:   r.Duration.Round(time.Millisecond).String(),
		TotalTests: r.TotalTests,
		Summary:    summary(r.Findings),
		Findings:   r.Findings,
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	return string(b), err
}

// ── SARIF 2.1.0 ───────────────────────────────────────────────────────────────

type sarif struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID  string          `json:"ruleId"`
	Level   string          `json:"level"`
	Message sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func toSARIF(r scanner.ScanResult) (string, error) {
	var results []sarifResult
	ruleSet := map[string]bool{}
	var rules []sarifRule

	for _, f := range r.Findings {
		ruleID := sarifRuleID(f.Category)
		if !ruleSet[ruleID] {
			ruleSet[ruleID] = true
			rules = append(rules, sarifRule{ID: ruleID, Name: f.Category})
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Endpoint},
				},
			}},
		})
	}

	s := sarif{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "APISentry",
				Version: "1.0.0",
				Rules:   rules,
			}},
			Results: results,
		}},
	}
	b, err := json.MarshalIndent(s, "", "  ")
	return string(b), err
}

func sarifRuleID(category string) string {
	// NOTE: API5 must be checked before API2. "Broken Function Auth" contains "Auth"
	// which would incorrectly match the API2 case if evaluated first.
	switch {
	case strings.Contains(category, "API1"), strings.Contains(category, "BOLA"):
		return "OWASP-API1"
	case strings.Contains(category, "API5"), strings.Contains(category, "Function"):
		return "OWASP-API5"
	case strings.Contains(category, "API2"), strings.Contains(category, "Broken Auth"):
		return "OWASP-API2"
	case strings.Contains(category, "API3"), strings.Contains(category, "Mass"):
		return "OWASP-API3"
	case strings.Contains(category, "API4"), strings.Contains(category, "Rate"):
		return "OWASP-API4"
	case strings.Contains(category, "API6"), strings.Contains(category, "Injection"):
		return "OWASP-API6"
	case strings.Contains(category, "API7"), strings.Contains(category, "SSRF"):
		return "OWASP-API7"
	case strings.Contains(category, "API8"), strings.Contains(category, "Misconfiguration"):
		return "OWASP-API8"
	case strings.Contains(category, "API9"), strings.Contains(category, "Inventory"):
		return "OWASP-API9"
	default:
		return "OWASP-API-UNKNOWN"
	}
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// ── HTML ──────────────────────────────────────────────────────────────────────

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APISentry Security Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;padding:32px}
h1{font-size:1.8rem;color:#7dd3fc;margin-bottom:4px}
.meta{color:#64748b;font-size:.85rem;margin-bottom:32px}
.summary{display:flex;gap:16px;margin-bottom:32px;flex-wrap:wrap}
.badge{padding:12px 20px;border-radius:8px;font-weight:700;font-size:1.1rem;min-width:100px;text-align:center}
.badge.critical{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}
.badge.high{background:#431407;color:#fdba74;border:1px solid #7c2d12}
.badge.medium{background:#422006;color:#fcd34d;border:1px solid #78350f}
.badge.low{background:#052e16;color:#86efac;border:1px solid #14532d}
.badge .label{font-size:.7rem;font-weight:400;display:block;margin-top:2px;opacity:.7}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{background:#1e293b;color:#94a3b8;text-align:left;padding:10px 12px;font-weight:600;border-bottom:2px solid #334155}
td{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover td{background:#1a2535}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}
.sev.CRITICAL{background:#7f1d1d;color:#fca5a5}
.sev.HIGH{background:#7c2d12;color:#fdba74}
.sev.MEDIUM{background:#78350f;color:#fcd34d}
.sev.LOW{background:#14532d;color:#86efac}
.conf{color:#64748b;font-size:.75rem}
.evidence{font-family:monospace;font-size:.75rem;color:#94a3b8;margin-top:4px}
footer{margin-top:40px;color:#334155;font-size:.75rem;text-align:center}
</style>
</head>
<body>
<h1>APISentry Security Report</h1>
<p class="meta">Target: {{.Target}} &nbsp;|&nbsp; Spec: {{.SpecFile}} &nbsp;|&nbsp; Scanned: {{.ScannedAt.Format "2006-01-02 15:04:05 UTC"}} &nbsp;|&nbsp; Duration: {{.Duration}} &nbsp;|&nbsp; Tests: {{.TotalTests}}</p>

<div class="summary">
  <div class="badge critical"><span>{{index .Summary "CRITICAL"}}</span><span class="label">CRITICAL</span></div>
  <div class="badge high"><span>{{index .Summary "HIGH"}}</span><span class="label">HIGH</span></div>
  <div class="badge medium"><span>{{index .Summary "MEDIUM"}}</span><span class="label">MEDIUM</span></div>
  <div class="badge low"><span>{{index .Summary "LOW"}}</span><span class="label">LOW</span></div>
</div>

{{if .Findings}}
<table>
<thead><tr><th>#</th><th>Severity</th><th>Category</th><th>Method</th><th>Endpoint</th><th>Description</th><th>Confidence</th></tr></thead>
<tbody>
{{range $i, $f := .Findings}}
<tr>
  <td>{{add $i 1}}</td>
  <td><span class="sev {{$f.Severity}}">{{$f.Severity}}</span></td>
  <td>{{$f.Category}}</td>
  <td><code>{{$f.Method}}</code></td>
  <td><code>{{$f.Endpoint}}</code></td>
  <td>{{$f.Description}}{{if $f.Evidence}}<div class="evidence">{{$f.Evidence}}</div>{{end}}</td>
  <td><span class="conf">{{$f.Confidence}}%</span></td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p style="color:#22c55e;font-size:1.1rem">✅ No vulnerabilities found.</p>
{{end}}

<footer>Generated by APISentry v1.0.0 &nbsp;·&nbsp; OWASP API Top 10 &nbsp;·&nbsp; <a href="https://apisentry-web.vercel.app" style="color:#7dd3fc">APISentry</a></footer>
</body>
</html>`

func toHTML(r scanner.ScanResult) (string, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}).Parse(htmlTmpl)
	if err != nil {
		return "", err
	}

	data := struct {
		scanner.ScanResult
		Summary map[string]int
	}{r, summary(r.Findings)}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ── TEXT ──────────────────────────────────────────────────────────────────────

func toText(r scanner.ScanResult) string {
	s := summary(r.Findings)
	var sb strings.Builder
	fmt.Fprintf(&sb, "\n╔══════════════════════════════════════╗\n")
	fmt.Fprintf(&sb, "║           SCAN RESULTS               ║\n")
	fmt.Fprintf(&sb, "╚══════════════════════════════════════╝\n\n")
	fmt.Fprintf(&sb, "  Target:   %s\n", r.Target)
	fmt.Fprintf(&sb, "  Tests:    %d\n", r.TotalTests)
	fmt.Fprintf(&sb, "  Duration: %s\n\n", r.Duration.Round(time.Millisecond))
	fmt.Fprintf(&sb, "  CRITICAL: %d\n", s["CRITICAL"])
	fmt.Fprintf(&sb, "  HIGH:     %d\n", s["HIGH"])
	fmt.Fprintf(&sb, "  MEDIUM:   %d\n", s["MEDIUM"])
	fmt.Fprintf(&sb, "  LOW:      %d\n", s["LOW"])
	fmt.Fprintf(&sb, "  TOTAL:    %d\n\n", len(r.Findings))

	for i, f := range r.Findings {
		fmt.Fprintf(&sb, "[%d] %s — %s\n", i+1, f.Severity, f.Category)
		fmt.Fprintf(&sb, "    %s %s → HTTP %d (confidence: %d%%)\n", f.Method, f.Endpoint, f.StatusCode, f.Confidence)
		fmt.Fprintf(&sb, "    %s\n\n", f.Description)
	}
	return sb.String()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func summary(findings []scanner.Finding) map[string]int {
	m := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range findings {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}
