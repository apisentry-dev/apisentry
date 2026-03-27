package attacks

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/apisentry-dev/apisentry/internal/parser"
)

// BOLATest represents a single BOLA (Broken Object Level Authorization) test case
type BOLATest struct {
	Name        string
	Method      string
	URL         string
	Description string
	OriginalID  string
	TestID      string
}

// alternativeIDs are values to substitute for path IDs to test BOLA
var alternativeIDs = []string{"1", "2", "99", "100", "9999", "0", "-1"}

// GenerateBOLATests generates BOLA test cases for endpoints with path ID parameters
func GenerateBOLATests(endpoints []parser.Endpoint, baseURL string) []BOLATest {
	var tests []BOLATest

	for _, ep := range endpoints {
		// BOLA only meaningful on auth-protected endpoints
		if !ep.RequiresAuth {
			continue
		}
		pathIDs := extractPathIDs(ep)
		if len(pathIDs) == 0 {
			continue
		}

		for _, param := range pathIDs {
			for _, altID := range alternativeIDs {
				url := buildURL(baseURL, ep.Path, param.Name, altID)
				tests = append(tests, BOLATest{
					Name:        fmt.Sprintf("BOLA_%s_%s_%s", ep.Method, sanitizePath(ep.Path), altID),
					Method:      ep.Method,
					URL:         url,
					Description: fmt.Sprintf("BOLA: access %s %s with %s=%s (unauthorized object)", ep.Method, ep.Path, param.Name, altID),
					OriginalID:  param.Name,
					TestID:      altID,
				})
			}
		}
	}

	return tests
}

// extractPathIDs returns parameters that look like object IDs (in path, integer or uuid type)
func extractPathIDs(ep parser.Endpoint) []parser.Parameter {
	var ids []parser.Parameter
	for _, p := range ep.Parameters {
		if p.In != "path" {
			continue
		}
		if p.Type == "integer" || p.Type == "string" || p.Type == "object" || p.Type == "unknown" {
			if isIDLike(p.Name) {
				ids = append(ids, p)
			}
		}
	}
	return ids
}

// isIDLike checks if a parameter name looks like an object identifier
func isIDLike(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, "id") ||
		strings.HasSuffix(lower, "_id") ||
		strings.HasSuffix(lower, "uuid") ||
		lower == "id"
}

// buildURL replaces the path parameter placeholder with the test value
func buildURL(base, path, paramName, value string) string {
	base = strings.TrimRight(base, "/")
	replaced := strings.ReplaceAll(path, "{"+paramName+"}", value)
	return base + replaced
}

// sanitizePath makes a path safe for use in test names
func sanitizePath(path string) string {
	r := strings.NewReplacer("/", "_", "{", "", "}", "")
	return strings.Trim(r.Replace(path), "_")
}

// ExecuteBOLATest sends the HTTP request and returns the response status code
func ExecuteBOLATest(test BOLATest, token string) (int, error) {
	req, err := http.NewRequest(test.Method, test.URL, nil)
	if err != nil {
		return 0, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
