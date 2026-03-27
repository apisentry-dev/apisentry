package attacks

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apisentry-dev/apisentry/internal/parser"
)

// FuncAuthTest represents a broken function level authorization test case
type FuncAuthTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Description string
	TestType    string // "admin_access", "method_override", "http_verb_tamper"
}

// adminPathPatterns are URL patterns that suggest admin-only functionality
var adminPathPatterns = []string{
	"/admin", "/api/admin", "/api/v1/admin", "/api/v2/admin",
	"/management", "/internal", "/superuser", "/root",
	"/system", "/config", "/settings/admin",
	"/users/all", "/users/list",
}

// extraHTTPMethods are truly non-standard methods to probe for misconfigured servers.
// OPTIONS and HEAD are standard HTTP methods (used for CORS preflight and metadata);
// CORS is checked separately in misconfig. Only TRACE is a real security concern.
var extraHTTPMethods = []string{"TRACE"}

// GenerateFuncAuthTests generates broken function level authorization test cases
func GenerateFuncAuthTests(endpoints []parser.Endpoint, baseURL string) []FuncAuthTest {
	var tests []FuncAuthTest

	// Track which paths we've already seen to avoid duplicates
	seenPaths := map[string]bool{}
	// Track which HTTP methods exist per path (to find missing method restrictions)
	pathMethods := map[string][]string{}
	for _, ep := range endpoints {
		pathMethods[ep.Path] = append(pathMethods[ep.Path], ep.Method)
	}

	for _, ep := range endpoints {
		url := buildEndpointURL(baseURL, ep.Path)

		// 1. Admin endpoint access with a regular user token
		if isAdminPath(ep.Path) && !seenPaths[ep.Path+":admin"] {
			seenPaths[ep.Path+":admin"] = true
			tests = append(tests, FuncAuthTest{
				Name:        fmt.Sprintf("FUNC_AUTH_ADMIN_%s_%s", ep.Method, sanitizePath(ep.Path)),
				Method:      ep.Method,
				URL:         url,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Admin access: attempt %s %s with no/user token (admin path)", ep.Method, ep.Path),
				TestType:    "admin_access",
			})
		}

		// 2. Try write methods (PUT/DELETE/PATCH) on paths that only declare GET
		if ep.Method == "GET" {
			existingMethods := pathMethods[ep.Path]
			for _, writeMethod := range []string{"PUT", "DELETE", "PATCH", "POST"} {
				if !containsMethod(existingMethods, writeMethod) {
					key := ep.Path + ":" + writeMethod
					if !seenPaths[key] {
						seenPaths[key] = true
						tests = append(tests, FuncAuthTest{
							Name:        fmt.Sprintf("FUNC_AUTH_METHOD_%s_%s", writeMethod, sanitizePath(ep.Path)),
							Method:      writeMethod,
							URL:         url,
							Headers:     map[string]string{"Content-Type": "application/json"},
							Description: fmt.Sprintf("Method override: %s on %s (only GET is declared — may lack authz)", writeMethod, ep.Path),
							TestType:    "method_override",
						})
					}
				}
			}
		}

		// 3. HTTP verb tampering (OPTIONS, TRACE) — probe once per unique path
		if !seenPaths[ep.Path+":verb"] {
			seenPaths[ep.Path+":verb"] = true
			for _, method := range extraHTTPMethods {
				tests = append(tests, FuncAuthTest{
					Name:        fmt.Sprintf("FUNC_AUTH_VERB_%s_%s", method, sanitizePath(ep.Path)),
					Method:      method,
					URL:         url,
					Headers:     map[string]string{},
					Description: fmt.Sprintf("HTTP verb tamper: %s %s — check for unexpected 2xx or data leak", method, ep.Path),
					TestType:    "http_verb_tamper",
				})
			}
		}
	}

	// 4. Probe common admin paths that are NOT in the spec (hidden endpoints)
	base := strings.TrimRight(baseURL, "/")
	for _, adminPath := range adminPathPatterns {
		for _, method := range []string{"GET", "POST"} {
			key := adminPath + ":" + method
			if !seenPaths[key] {
				seenPaths[key] = true
				tests = append(tests, FuncAuthTest{
					Name:        fmt.Sprintf("FUNC_AUTH_HIDDEN_%s_%s", method, sanitizePath(adminPath)),
					Method:      method,
					URL:         base + adminPath,
					Headers:     map[string]string{},
					Description: fmt.Sprintf("Hidden admin endpoint: probe undocumented %s %s", method, adminPath),
					TestType:    "admin_access",
				})
			}
		}
	}

	return tests
}

func isAdminPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "admin") ||
		strings.Contains(lower, "internal") ||
		strings.Contains(lower, "management") ||
		strings.Contains(lower, "superuser")
}

func containsMethod(methods []string, target string) bool {
	for _, m := range methods {
		if m == target {
			return true
		}
	}
	return false
}

// ExecuteFuncAuthTest sends the HTTP request and returns the status code
func ExecuteFuncAuthTest(test FuncAuthTest, token string) (int, error) {
	req, err := http.NewRequest(test.Method, test.URL, strings.NewReader("{}"))
	if err != nil {
		return 0, err
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
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// IsFuncAuthVulnerable returns true if access was unexpectedly granted
func IsFuncAuthVulnerable(statusCode int, testType string) bool {
	switch testType {
	case "admin_access", "method_override":
		// 2xx = access granted = vulnerability
		return statusCode >= 200 && statusCode < 300
	case "http_verb_tamper":
		// 200 on TRACE = potential XST vulnerability
		// Anything other than 405 Method Not Allowed is suspicious
		return statusCode >= 200 && statusCode < 300
	}
	return false
}
