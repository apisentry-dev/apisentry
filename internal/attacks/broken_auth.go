package attacks

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/apisentry-dev/apisentry/internal/parser"
)

// BrokenAuthTest represents a single Broken Authentication test case
type BrokenAuthTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Description string
	TestType    string // "no_auth", "invalid_token", "expired_token", "empty_token"
}

var invalidTokens = []struct {
	name  string
	value string
}{
	{"invalid_token", "Bearer invalid.token.here"},
	{"empty_bearer", "Bearer "},
	{"null_token", "Bearer null"},
	{"none_token", "Bearer none"},
	{"wrong_format", "Token abc123"},
}

// GenerateBrokenAuthTests generates auth bypass test cases for protected endpoints
func GenerateBrokenAuthTests(endpoints []parser.Endpoint, baseURL string) []BrokenAuthTest {
	var tests []BrokenAuthTest

	for _, ep := range endpoints {
		url := buildEndpointURL(baseURL, ep.Path)

		// Test 1: No auth header at all (on auth-required endpoints)
		if ep.RequiresAuth {
			tests = append(tests, BrokenAuthTest{
				Name:        fmt.Sprintf("BROKEN_AUTH_no_token_%s_%s", ep.Method, sanitizePath(ep.Path)),
				Method:      ep.Method,
				URL:         url,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Auth bypass: %s %s with NO auth token (endpoint requires auth)", ep.Method, ep.Path),
				TestType:    "no_auth",
			})
		}

		// Test 2: Invalid/malformed tokens (only on auth-required endpoints)
		if ep.RequiresAuth {
			for _, tok := range invalidTokens {
				tests = append(tests, BrokenAuthTest{
					Name:        fmt.Sprintf("BROKEN_AUTH_%s_%s_%s", tok.name, ep.Method, sanitizePath(ep.Path)),
					Method:      ep.Method,
					URL:         url,
					Headers:     map[string]string{"Authorization": tok.value},
					Description: fmt.Sprintf("Auth bypass: %s %s with %s", ep.Method, ep.Path, tok.name),
					TestType:    "invalid_token",
				})
			}
		}
	}

	return tests
}

// buildEndpointURL replaces path params with placeholder values for auth testing
func buildEndpointURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	// Replace {param} placeholders with test values
	result := path
	for strings.Contains(result, "{") {
		start := strings.Index(result, "{")
		end := strings.Index(result, "}")
		if start == -1 || end == -1 {
			break
		}
		result = result[:start] + "1" + result[end+1:]
	}
	return base + result
}

// ExecuteBrokenAuthTest sends the HTTP request and returns the status code
func ExecuteBrokenAuthTest(test BrokenAuthTest) (int, error) {
	req, err := http.NewRequest(test.Method, test.URL, nil)
	if err != nil {
		return 0, err
	}

	for k, v := range test.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "APISentry-Scanner/1.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// IsBrokenAuthVulnerable checks if a response status indicates a potential auth bypass
func IsBrokenAuthVulnerable(statusCode int) bool {
	// 200, 201, 202 = success despite missing/invalid auth = VULNERABILITY
	// 400 = bad request (may have hit the endpoint) = potential issue
	// 401, 403 = correctly rejected = NOT vulnerable
	// 404 = not found = inconclusive
	return statusCode >= 200 && statusCode < 300
}
