package scanner

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apisentry-dev/apisentry/internal/attacks"
	"github.com/apisentry-dev/apisentry/internal/engine"
)

// Finding represents a confirmed or potential vulnerability
type Finding struct {
	Severity    string
	Category    string
	Endpoint    string
	Method      string
	Description string
	Evidence    string // HTTP request/response snippet
	StatusCode  int
	Confidence  int // 0-100
}

// ScanResult holds all findings from a scan
type ScanResult struct {
	Findings  []Finding
	ScannedAt time.Time
	Duration  time.Duration
	Target    string
	SpecFile  string
	TotalTests int
}

// Execute runs all attack cases from a plan and returns findings
func Execute(ctx context.Context, plan engine.Plan, cfg Config) ScanResult {
	client := NewClient(cfg)
	start := time.Now()

	var mu sync.Mutex
	var findings []Finding
	var wg sync.WaitGroup
	var done int64

	sem := make(chan struct{}, cfg.Concurrency)

	for _, cas := range plan.Cases {
		wg.Add(1)
		sem <- struct{}{}
		go func(c engine.AttackCase) {
			defer wg.Done()
			defer func() { <-sem }()
			defer atomic.AddInt64(&done, 1)

			if f := executeCase(ctx, client, c, cfg.Token); f != nil {
				mu.Lock()
				findings = append(findings, *f)
				mu.Unlock()
			}
		}(cas)
	}

	wg.Wait()

	return ScanResult{
		Findings:   dedup(findings),
		ScannedAt:  start,
		Duration:   time.Since(start),
		TotalTests: len(plan.Cases),
	}
}

func executeCase(ctx context.Context, client *Client, c engine.AttackCase, token string) *Finding {
	switch {
	case c.BOLATest != nil:
		resp := client.Do(ctx, c.Method, c.URL, c.Headers, "")
		if resp.Err != nil {
			return nil
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &Finding{
				Severity:    "HIGH",
				Category:    c.Category,
				Endpoint:    c.URL,
				Method:      c.Method,
				Description: c.Description,
				Evidence:    fmt.Sprintf("HTTP %d", resp.StatusCode),
				StatusCode:  resp.StatusCode,
				Confidence:  70,
			}
		}

	case c.AuthTest != nil:
		resp := client.Do(ctx, c.Method, c.URL, c.Headers, "")
		if resp.Err != nil {
			return nil
		}
		if attacks.IsBrokenAuthVulnerable(resp.StatusCode) {
			return &Finding{
				Severity:    "CRITICAL",
				Category:    c.Category,
				Endpoint:    c.URL,
				Method:      c.Method,
				Description: c.Description,
				Evidence:    fmt.Sprintf("HTTP %d — auth bypass succeeded", resp.StatusCode),
				StatusCode:  resp.StatusCode,
				Confidence:  85,
			}
		}

	case c.PropertyTest != nil:
		resp := client.Do(ctx, c.Method, c.URL, c.Headers, c.Body)
		if resp.Err != nil {
			return nil
		}
		if c.PropertyTest.TestType == "mass_assignment" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &Finding{
				Severity:    "HIGH",
				Category:    "Mass Assignment (API3:2023)",
				Endpoint:    c.URL,
				Method:      c.Method,
				Description: c.Description,
				Evidence:    fmt.Sprintf("HTTP %d — server accepted privileged fields", resp.StatusCode),
				StatusCode:  resp.StatusCode,
				Confidence:  65,
			}
		}
		if c.PropertyTest.TestType == "exposure_check" {
			if leaked := FindSensitiveFields(resp.Body); len(leaked) > 0 {
				return &Finding{
					Severity:    "HIGH",
					Category:    "Excessive Data Exposure (API3:2023)",
					Endpoint:    c.URL,
					Method:      c.Method,
					Description: fmt.Sprintf("%s — leaked fields: %v", c.Description, leaked),
					Evidence:    fmt.Sprintf("HTTP %d — response contains: %v", resp.StatusCode, leaked),
					StatusCode:  resp.StatusCode,
					Confidence:  90,
				}
			}
		}

	case c.RateLimitTest != nil:
		if c.RateLimitTest.TestType == "rate_limit" {
			result, err := attacks.ExecuteRateLimitBurst(*c.RateLimitTest, token, 20)
			if err != nil {
				return nil
			}
			if attacks.IsRateLimitVulnerable(result) {
				return &Finding{
					Severity:    "MEDIUM",
					Category:    c.Category,
					Endpoint:    c.URL,
					Method:      c.Method,
					Description: c.Description,
					Evidence:    fmt.Sprintf("20 requests sent, no HTTP 429 received"),
					StatusCode:  200,
					Confidence:  80,
				}
			}
		} else {
			resp := client.Do(ctx, c.Method, c.URL, c.Headers, c.Body)
			if resp.Err != nil {
				return nil
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				sev := "LOW"
				if c.RateLimitTest.TestType == "pagination_abuse" {
					sev = "MEDIUM"
				}
				return &Finding{
					Severity:    sev,
					Category:    c.Category,
					Endpoint:    c.URL,
					Method:      c.Method,
					Description: c.Description,
					Evidence:    fmt.Sprintf("HTTP %d", resp.StatusCode),
					StatusCode:  resp.StatusCode,
					Confidence:  75,
				}
			}
		}

	case c.FuncAuthTest != nil:
		resp := client.Do(ctx, c.Method, c.URL, c.Headers, "{}")
		if resp.Err != nil {
			return nil
		}
		if attacks.IsFuncAuthVulnerable(resp.StatusCode, c.FuncAuthTest.TestType) {
			return &Finding{
				Severity:    c.Severity,
				Category:    c.Category,
				Endpoint:    c.URL,
				Method:      c.Method,
				Description: c.Description,
				Evidence:    fmt.Sprintf("HTTP %d — unexpected access granted", resp.StatusCode),
				StatusCode:  resp.StatusCode,
				Confidence:  75,
			}
		}

	case c.InjectionTest != nil:
		status, body, err := attacks.ExecuteInjectionTest(*c.InjectionTest, token)
		if err != nil {
			return nil
		}
		if attacks.IsInjectionVulnerable(status, body, c.InjectionTest.TestType, c.InjectionTest.Payload) {
			sev := c.Severity
			return &Finding{
				Severity:    sev,
				Category:    c.Category,
				Endpoint:    c.URL,
				Method:      c.Method,
				Description: c.Description,
				Evidence:    fmt.Sprintf("HTTP %d — injection indicator in response", status),
				StatusCode:  status,
				Confidence:  70,
			}
		}

	case c.SSRFTest != nil:
		status, body, err := attacks.ExecuteSSRFTest(*c.SSRFTest, token)
		if err != nil {
			return nil
		}
		if attacks.IsSSRFVulnerable(status, body) {
			return &Finding{
				Severity:    "CRITICAL",
				Category:    c.Category,
				Endpoint:    c.URL,
				Method:      c.Method,
				Description: c.Description,
				Evidence:    fmt.Sprintf("HTTP %d — cloud metadata or internal resource content in response", status),
				StatusCode:  status,
				Confidence:  95,
			}
		}

	case c.MisconfigTest != nil:
		status, headers, body, err := attacks.ExecuteMisconfigTest(*c.MisconfigTest, token)
		if err != nil {
			return nil
		}
		switch c.MisconfigTest.TestType {
		case "security_headers":
			missing := attacks.MissingSecurityHeaders(headers)
			if len(missing) >= 2 && status >= 200 && status < 300 {
				return &Finding{
					Severity:    "LOW",
					Category:    c.Category,
					Endpoint:    c.URL,
					Method:      c.Method,
					Description: fmt.Sprintf("%s — missing headers: %v", c.Description, missing),
					Evidence:    fmt.Sprintf("HTTP %d — %d security headers absent", status, len(missing)),
					StatusCode:  status,
					Confidence:  85,
				}
			}
		case "cors":
			if attacks.HasOpenCORS(headers, "https://evil.attacker.com") {
				return &Finding{
					Severity:    "MEDIUM",
					Category:    c.Category,
					Endpoint:    c.URL,
					Method:      c.Method,
					Description: fmt.Sprintf("%s — Access-Control-Allow-Origin: %s", c.Description, headers.Get("Access-Control-Allow-Origin")),
					Evidence:    fmt.Sprintf("HTTP %d — CORS reflects arbitrary origin", status),
					StatusCode:  status,
					Confidence:  90,
				}
			}
		case "debug_endpoint":
			if status >= 200 && status < 300 {
				return &Finding{
					Severity:    "HIGH",
					Category:    c.Category,
					Endpoint:    c.URL,
					Method:      c.Method,
					Description: c.Description,
					Evidence:    fmt.Sprintf("HTTP %d — sensitive endpoint is publicly accessible", status),
					StatusCode:  status,
					Confidence:  80,
				}
			}
		case "verbose_error":
			if attacks.HasVerboseError(body) {
				return &Finding{
					Severity:    "MEDIUM",
					Category:    c.Category,
					Endpoint:    c.URL,
					Method:      c.Method,
					Description: c.Description,
					Evidence:    fmt.Sprintf("HTTP %d — stack trace or DB error in response", status),
					StatusCode:  status,
					Confidence:  85,
				}
			}
		}

	case c.InventoryTest != nil:
		status, _, err := attacks.ExecuteInventoryTest(*c.InventoryTest, token)
		if err != nil {
			return nil
		}
		if attacks.IsInventoryVulnerable(status) {
			return &Finding{
				Severity:    c.Severity,
				Category:    c.Category,
				Endpoint:    c.URL,
				Method:      c.Method,
				Description: c.Description,
				Evidence:    fmt.Sprintf("HTTP %d — undocumented endpoint responded", status),
				StatusCode:  status,
				Confidence:  65,
			}
		}

	default:
		resp := client.Do(ctx, c.Method, c.URL, c.Headers, c.Body)
		if resp.Err != nil || resp.StatusCode == http.StatusNotFound {
			return nil
		}
		_ = http.StatusNotFound
	}

	return nil
}

func dedup(findings []Finding) []Finding {
	seen := map[string]bool{}
	var result []Finding
	for _, f := range findings {
		key := f.Method + "|" + f.Category + "|" + f.Endpoint
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}
