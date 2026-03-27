package attacks

// API6:2023 — Unrestricted Access to Sensitive Business Flows
// API10:2023 — Unsafe Consumption of APIs (injection via third-party data)
//
// Tests for: SQL injection, NoSQL injection, command injection,
// XSS in API responses, template injection — all via API parameters.

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apisentry-dev/apisentry/internal/parser"
)

// InjectionTest represents an injection / business flow abuse test
type InjectionTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Description string
	TestType    string // "sqli", "nosqli", "xss", "template", "business_flow"
	Payload     string
}

var sqlPayloads = []string{
	"'", "''", "' OR '1'='1", `" OR "1"="1`, `' OR 1=1--`,
	`'; DROP TABLE users--`, `1' AND SLEEP(3)--`,
}

var nosqlPayloads = []string{
	`{"$gt": ""}`, `{"$ne": null}`, `{"$regex": ".*"}`,
	`{"$where": "sleep(3000)"}`,
}

var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`javascript:alert(1)`,
}

// templatePayloads use a unique multiplication result (7907*6271 = 49584797)
// that is unlikely to appear naturally in API responses.
var templatePayloads = []string{
	`{{7907*6271}}`, `${7907*6271}`, `<%= 7907*6271 %>`, `#{7907*6271}`,
}

// businessFlowAbusePaths are high-value endpoints worth extra probing
var businessFlowAbusePaths = []string{
	"/api/coupon", "/api/promo", "/api/discount",
	"/api/transfer", "/api/payment", "/api/checkout",
	"/api/referral", "/api/invite",
	"/api/vote", "/api/like", "/api/rating",
	"/api/export", "/api/bulk", "/api/batch",
}

// GenerateInjectionTests generates injection and business flow tests
func GenerateInjectionTests(endpoints []parser.Endpoint, baseURL string) []InjectionTest {
	var tests []InjectionTest
	base := strings.TrimRight(baseURL, "/")

	for _, ep := range endpoints {
		url := buildEndpointURL(base, ep.Path)

		// SQL / NoSQL injection in query parameters
		for _, param := range ep.Parameters {
			if param.In != "query" {
				continue
			}
			// SQL injection
			for _, payload := range sqlPayloads[:3] { // top 3 to avoid noise
				injected := injectQueryParam(url, param.Name, payload)
				tests = append(tests, InjectionTest{
					Name:        fmt.Sprintf("SQLI_%s_%s", sanitizePath(ep.Path), param.Name),
					Method:      ep.Method,
					URL:         injected,
					Headers:     map[string]string{},
					Description: fmt.Sprintf("SQL injection: %s %s param '%s' = %q", ep.Method, ep.Path, param.Name, payload),
					TestType:    "sqli",
					Payload:     payload,
				})
			}
		}

		// NoSQL injection in JSON body
		if ep.RequestBody != nil && (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") {
			for _, prop := range ep.RequestBody.Properties {
				for _, payload := range nosqlPayloads[:2] {
					body := fmt.Sprintf(`{"%s": %s}`, prop, payload)
					tests = append(tests, InjectionTest{
						Name:        fmt.Sprintf("NOSQLI_%s_%s_%s", ep.Method, sanitizePath(ep.Path), prop),
						Method:      ep.Method,
						URL:         url,
						Headers:     map[string]string{"Content-Type": "application/json"},
						Body:        body,
						Description: fmt.Sprintf("NoSQL injection: %s %s body field '%s' = %s", ep.Method, ep.Path, prop, payload),
						TestType:    "nosqli",
						Payload:     payload,
					})
				}
			}

			// Template injection in first string field
			if len(ep.RequestBody.Properties) > 0 {
				prop := ep.RequestBody.Properties[0]
				for _, payload := range templatePayloads[:2] {
					body := fmt.Sprintf(`{"%s": "%s"}`, prop, payload)
					tests = append(tests, InjectionTest{
						Name:        fmt.Sprintf("TMPL_%s_%s", sanitizePath(ep.Path), prop),
						Method:      ep.Method,
						URL:         url,
						Headers:     map[string]string{"Content-Type": "application/json"},
						Body:        body,
						Description: fmt.Sprintf("Template injection: %s %s body field '%s' = %q", ep.Method, ep.Path, prop, payload),
						TestType:    "template",
						Payload:     payload,
					})
				}
			}
		}
	}

	// Business flow abuse — probe high-value paths not in spec
	for _, path := range businessFlowAbusePaths {
		for _, method := range []string{"GET", "POST"} {
			tests = append(tests, InjectionTest{
				Name:        fmt.Sprintf("BIZ_FLOW_%s_%s", method, sanitizePath(path)),
				Method:      method,
				URL:         base + path,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Business flow: probe undocumented %s %s (coupon/payment/export abuse)", method, path),
				TestType:    "business_flow",
			})
		}
	}

	return tests
}

// ExecuteInjectionTest sends the request
func ExecuteInjectionTest(test InjectionTest, token string) (int, string, error) {
	var body *strings.Reader
	if test.Body != "" {
		body = strings.NewReader(test.Body)
	} else {
		body = strings.NewReader("")
	}

	req, err := http.NewRequest(test.Method, test.URL, body)
	if err != nil {
		return 0, "", err
	}

	for k, v := range test.Headers {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "APISentry-Scanner/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	var bufBytes bytes.Buffer
	bufBytes.ReadFrom(resp.Body)
	return resp.StatusCode, bufBytes.String(), nil
}

// IsInjectionVulnerable checks response for injection indicators
func IsInjectionVulnerable(statusCode int, body, testType, payload string) bool {
	lower := strings.ToLower(body)
	switch testType {
	case "sqli":
		return strings.Contains(lower, "sql") && strings.Contains(lower, "error") ||
			strings.Contains(lower, "syntax error") ||
			strings.Contains(lower, "mysql") ||
			strings.Contains(lower, "postgresql") ||
			strings.Contains(lower, "ora-") ||
			strings.Contains(lower, "sqlite")
	case "nosqli":
		// Look for MongoDB-specific error patterns or data returned without proper filtering
		// Avoid FP: don't flag 200 alone (echo APIs would all fire)
		return strings.Contains(lower, "cast to objectid") ||
			strings.Contains(lower, "bson") ||
			strings.Contains(lower, "mongo") ||
			strings.Contains(lower, "$where") ||
			(statusCode >= 200 && statusCode < 300 && strings.Contains(lower, "\"_id\""))
	case "template":
		// Template evaluated: {{7907*6271}} → 49584797 (unique enough to avoid FP)
		return strings.Contains(body, "49584797")
	case "business_flow":
		return statusCode >= 200 && statusCode < 300
	}
	return false
}
