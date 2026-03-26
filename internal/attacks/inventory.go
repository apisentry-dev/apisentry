package attacks

// API9:2023 — Improper Inventory Management
// Probes for shadow/undocumented API versions, deprecated endpoints,
// and paths exposed outside the documented spec.

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apisentry/apisentry/internal/parser"
)

// InventoryTest represents an improper inventory management test
type InventoryTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Description string
	TestType    string // "shadow_version", "deprecated_path", "undoc_env"
}

// versionPrefixes are common API versioning patterns to probe
var versionPrefixes = []string{
	"/v0", "/v1", "/v2", "/v3", "/v4",
	"/api/v0", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
	"/api/internal", "/api/private", "/api/dev", "/api/test",
	"/api/beta", "/api/alpha", "/api/staging",
	"/internal", "/private", "/admin/api",
}

// deprecatedSuffixes are common old-version path patterns
var deprecatedSuffixes = []string{
	"_old", "_legacy", "_deprecated", "_v1", "_backup",
	".bak", ".old", "_copy",
}

// shadowEnvPaths are environment-specific endpoints that may be accidentally exposed
var shadowEnvPaths = []string{
	"/api/test/", "/api/dev/", "/api/staging/",
	"/test/", "/dev/", "/staging/", "/uat/",
	"/sandbox/", "/qa/",
}

// GenerateInventoryTests generates improper inventory management tests
func GenerateInventoryTests(endpoints []parser.Endpoint, baseURL string) []InventoryTest {
	var tests []InventoryTest
	base := strings.TrimRight(baseURL, "/")

	// Build set of known documented paths
	docPaths := map[string]bool{}
	for _, ep := range endpoints {
		docPaths[ep.Path] = true
	}

	// Detect version prefix used in documented endpoints
	detectedVersion := detectAPIVersion(endpoints)

	// 1. Shadow API version probing — try adjacent versions of documented paths
	seen := map[string]bool{}
	for _, ep := range endpoints {
		// Extract the path suffix after the version prefix
		suffix := stripVersionPrefix(ep.Path)
		if suffix == "" || suffix == ep.Path {
			continue
		}

		for _, vp := range versionPrefixes {
			// Skip the version that's already documented
			if detectedVersion != "" && strings.HasPrefix(ep.Path, vp) {
				continue
			}
			probePath := vp + suffix
			if docPaths[probePath] {
				continue
			}
			key := ep.Method + probePath
			if seen[key] {
				continue
			}
			seen[key] = true
			tests = append(tests, InventoryTest{
				Name:        fmt.Sprintf("SHADOW_VER_%s_%s", ep.Method, sanitizePath(probePath)),
				Method:      ep.Method,
				URL:         base + probePath,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Shadow API version: probe %s %s (undocumented version of %s)", ep.Method, probePath, ep.Path),
				TestType:    "shadow_version",
			})
		}
	}

	// 2. Deprecated path variants — append legacy suffixes to documented endpoints
	// Skip paths with unresolved path parameters (contain '{') to avoid catch-all FPs
	for _, ep := range endpoints {
		if strings.Contains(ep.Path, "{") {
			continue
		}
		for _, sfx := range deprecatedSuffixes {
			path := ep.Path + sfx
			if docPaths[path] {
				continue
			}
			key := "GET" + path
			if seen[key] {
				continue
			}
			seen[key] = true
			tests = append(tests, InventoryTest{
				Name:        fmt.Sprintf("DEPR_%s", sanitizePath(path)),
				Method:      "GET",
				URL:         base + path,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Deprecated path: probe %s — old/backup version of documented endpoint %s", path, ep.Path),
				TestType:    "deprecated_path",
			})
		}
	}

	// 3. Shadow environment endpoints — dev/staging/test prefixes at root
	for _, envPath := range shadowEnvPaths {
		for _, ep := range endpoints {
			suffix := stripVersionPrefix(ep.Path)
			if suffix == "" {
				suffix = ep.Path
			}
			probePath := strings.TrimRight(envPath, "/") + suffix
			if docPaths[probePath] {
				continue
			}
			key := ep.Method + probePath
			if seen[key] {
				continue
			}
			seen[key] = true
			tests = append(tests, InventoryTest{
				Name:        fmt.Sprintf("SHADOW_ENV_%s_%s", ep.Method, sanitizePath(probePath)),
				Method:      ep.Method,
				URL:         base + probePath,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Shadow env endpoint: probe %s %s (dev/staging variant of %s)", ep.Method, probePath, ep.Path),
				TestType:    "undoc_env",
			})
		}
	}

	return tests
}

// detectAPIVersion returns the version prefix common to most endpoints (e.g. "/api/v2")
func detectAPIVersion(endpoints []parser.Endpoint) string {
	counts := map[string]int{}
	for _, ep := range endpoints {
		for _, vp := range versionPrefixes {
			if strings.HasPrefix(ep.Path, vp+"/") || ep.Path == vp {
				counts[vp]++
			}
		}
	}
	best, bestCount := "", 0
	for vp, c := range counts {
		if c > bestCount {
			best, bestCount = vp, c
		}
	}
	return best
}

// stripVersionPrefix removes the leading version segment from a path
func stripVersionPrefix(path string) string {
	for _, vp := range versionPrefixes {
		if strings.HasPrefix(path, vp+"/") {
			return path[len(vp):]
		}
	}
	return ""
}

// ExecuteInventoryTest sends the request and returns status + body
func ExecuteInventoryTest(test InventoryTest, token string) (int, string, error) {
	req, err := http.NewRequest(test.Method, test.URL, strings.NewReader(""))
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

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	return resp.StatusCode, "", nil
}

// IsInventoryVulnerable returns true if an undocumented endpoint responded successfully
func IsInventoryVulnerable(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}
