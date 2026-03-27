package attacks

// API8:2023 — Security Misconfiguration
// Tests for: missing security headers, exposed debug endpoints,
// verbose error messages, directory traversal, open CORS.

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apisentry-dev/apisentry/internal/parser"
)

// MisconfigTest represents a security misconfiguration test
type MisconfigTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Description string
	TestType    string
}

// debugPaths are common endpoints that should not be publicly accessible
var debugPaths = []string{
	"/debug", "/debug/pprof", "/debug/vars",
	"/.env", "/.env.local", "/.env.production",
	"/config.json", "/config.yaml", "/settings.json",
	"/api-docs", "/swagger", "/swagger-ui", "/swagger-ui.html",
	"/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml",
	"/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
	"/health", "/healthz", "/ready", "/readyz",
	"/metrics", "/prometheus",
	"/graphql", "/graphiql", "/playground",
	"/__debug__", "/_debug", "/admin/debug",
	"/phpinfo.php", "/info.php",
	"/server-status", "/server-info",
}

// GenerateMisconfigTests generates security misconfiguration tests
func GenerateMisconfigTests(endpoints []parser.Endpoint, baseURL string) []MisconfigTest {
	var tests []MisconfigTest
	base := strings.TrimRight(baseURL, "/")

	// 1. Security headers check (one test per endpoint)
	seen := map[string]bool{}
	for _, ep := range endpoints {
		url := buildEndpointURL(base, ep.Path)
		if !seen[ep.Path] {
			seen[ep.Path] = true
			tests = append(tests, MisconfigTest{
				Name:        fmt.Sprintf("HEADERS_%s_%s", ep.Method, sanitizePath(ep.Path)),
				Method:      ep.Method,
				URL:         url,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Security headers: check %s %s for missing X-Content-Type-Options, HSTS, X-Frame-Options, CSP", ep.Method, ep.Path),
				TestType:    "security_headers",
			})
		}
	}

	// 2. CORS misconfiguration — send arbitrary Origin header
	for _, ep := range endpoints {
		url := buildEndpointURL(base, ep.Path)
		key := "cors:" + ep.Path
		if !seen[key] {
			seen[key] = true
			tests = append(tests, MisconfigTest{
				Name:        fmt.Sprintf("CORS_%s_%s", ep.Method, sanitizePath(ep.Path)),
				Method:      ep.Method,
				URL:         url,
				Headers:     map[string]string{"Origin": "https://evil.attacker.com"},
				Description: fmt.Sprintf("CORS: %s %s — check if Access-Control-Allow-Origin reflects arbitrary origin", ep.Method, ep.Path),
				TestType:    "cors",
			})
		}
	}

	// 3. Probe debug/sensitive endpoints
	for _, path := range debugPaths {
		tests = append(tests, MisconfigTest{
			Name:        fmt.Sprintf("DEBUG_%s", sanitizePath(path)),
			Method:      "GET",
			URL:         base + path,
			Headers:     map[string]string{},
			Description: fmt.Sprintf("Exposed endpoint: probe %s for sensitive data or debug info", path),
			TestType:    "debug_endpoint",
		})
	}

	// 4. Verbose errors — send malformed requests to trigger stack traces
	for _, ep := range endpoints {
		if ep.RequestBody != nil {
			url := buildEndpointURL(base, ep.Path)
			key := "err:" + ep.Path
			if !seen[key] {
				seen[key] = true
				tests = append(tests, MisconfigTest{
					Name:        fmt.Sprintf("VERBOSE_ERR_%s_%s", ep.Method, sanitizePath(ep.Path)),
					Method:      ep.Method,
					URL:         url,
					Headers:     map[string]string{"Content-Type": "application/json"},
					Description: fmt.Sprintf("Verbose errors: send malformed JSON to %s %s — check for stack traces in response", ep.Method, ep.Path),
					TestType:    "verbose_error",
				})
			}
		}
	}

	return tests
}

// ExecuteMisconfigTest sends the request and returns status + headers + body
func ExecuteMisconfigTest(test MisconfigTest, token string) (int, http.Header, string, error) {
	body := ""
	if test.TestType == "verbose_error" {
		body = `{invalid json`
	}

	req, err := http.NewRequest(test.Method, test.URL, strings.NewReader(body))
	if err != nil {
		return 0, nil, "", err
	}

	for k, v := range test.Headers {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "APISentry-Scanner/1.0")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()

	var bufBytes bytes.Buffer
	bufBytes.ReadFrom(resp.Body)

	return resp.StatusCode, resp.Header, bufBytes.String(), nil
}

// MissingSecurityHeaders returns the list of missing important headers
func MissingSecurityHeaders(headers http.Header) []string {
	required := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "",
		"Strict-Transport-Security": "",
		"X-XSS-Protection":          "",
	}
	var missing []string
	for h := range required {
		if headers.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	return missing
}

// HasOpenCORS returns true if server reflects arbitrary Origin
func HasOpenCORS(headers http.Header, sentOrigin string) bool {
	acao := headers.Get("Access-Control-Allow-Origin")
	return acao == "*" || acao == sentOrigin
}

// HasVerboseError checks response for stack trace patterns
func HasVerboseError(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "stack trace") ||
		strings.Contains(lower, "traceback") ||
		strings.Contains(lower, "at com.") ||
		strings.Contains(lower, "at org.") ||
		strings.Contains(lower, "exception in thread") ||
		strings.Contains(lower, "goroutine ") ||
		strings.Contains(lower, "panic:") ||
		strings.Contains(lower, "syntaxerror") ||
		strings.Contains(lower, "database error") ||
		strings.Contains(lower, "sql syntax")
}
