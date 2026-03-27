package attacks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/apisentry-dev/apisentry/internal/parser"
)

// PropertyTest represents a mass assignment or excessive data exposure test case
type PropertyTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Description string
	TestType    string // "mass_assignment" or "exposure_check"
}

// sensitiveFieldNames are privileged fields attackers try to inject via mass assignment
var sensitiveFieldNames = []string{
	"role", "isAdmin", "is_admin", "admin",
	"balance", "credits", "verified", "is_verified",
	"status", "active", "is_active", "enabled",
	"permissions", "scope", "level", "tier",
}

// sensitiveResponsePatterns are field names that should NOT appear in API responses
var sensitiveResponsePatterns = []string{
	"password", "passwd", "pass",
	"ssn", "social_security",
	"credit_card", "card_number", "cvv",
	"secret", "private_key", "api_key",
	"token", "refresh_token", "access_token",
	"pin", "otp",
}

// GeneratePropertyTests generates mass assignment and excessive data exposure tests
func GeneratePropertyTests(endpoints []parser.Endpoint, baseURL string) []PropertyTest {
	var tests []PropertyTest

	for _, ep := range endpoints {
		url := buildEndpointURL(baseURL, ep.Path)

		// Mass assignment: only test auth-protected endpoints (public echo APIs would FP)
		if ep.RequiresAuth && (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") {
			tests = append(tests, massAssignmentTests(ep, url)...)
		}

		// Excessive data exposure: check GET responses for sensitive field names
		if ep.Method == "GET" {
			tests = append(tests, exposureCheckTest(ep, url))
		}
	}

	return tests
}

func massAssignmentTests(ep parser.Endpoint, url string) []PropertyTest {
	var tests []PropertyTest

	// Build a payload that includes all known properties PLUS sensitive escalation fields
	payload := map[string]interface{}{}

	// Include all declared fields with dummy values
	if ep.RequestBody != nil {
		for _, prop := range ep.RequestBody.Properties {
			payload[prop] = "test"
		}
	}

	// Inject sensitive privilege-escalation fields
	for _, field := range sensitiveFieldNames {
		payload[field] = true
	}
	payload["role"] = "admin"
	payload["balance"] = 99999
	payload["is_admin"] = true

	body, err := json.Marshal(payload)
	if err != nil {
		return tests
	}

	tests = append(tests, PropertyTest{
		Name:        fmt.Sprintf("MASS_ASSIGN_%s_%s", ep.Method, sanitizePath(ep.Path)),
		Method:      ep.Method,
		URL:         url,
		Headers:     map[string]string{"Content-Type": "application/json"},
		Body:        string(body),
		Description: fmt.Sprintf("Mass assignment: %s %s injecting privileged fields (role=admin, isAdmin=true, balance=99999)", ep.Method, ep.Path),
		TestType:    "mass_assignment",
	})

	return tests
}

func exposureCheckTest(ep parser.Endpoint, url string) PropertyTest {
	return PropertyTest{
		Name:        fmt.Sprintf("DATA_EXPOSURE_%s_%s", ep.Method, sanitizePath(ep.Path)),
		Method:      ep.Method,
		URL:         url,
		Headers:     map[string]string{},
		Body:        "",
		Description: fmt.Sprintf("Excessive data exposure: check %s %s response for sensitive fields (password, ssn, token, etc.)", ep.Method, ep.Path),
		TestType:    "exposure_check",
	}
}

// ExecutePropertyTest sends the HTTP request and returns the status code and response body
func ExecutePropertyTest(test PropertyTest, token string) (int, string, error) {
	var bodyReader *bytes.Reader
	if test.Body != "" {
		bodyReader = bytes.NewReader([]byte(test.Body))
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(test.Method, test.URL, bodyReader)
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	respBody := buf.String()

	return resp.StatusCode, respBody, nil
}

// HasExcessiveDataExposure checks a response body for sensitive field names
func HasExcessiveDataExposure(respBody string) []string {
	lower := strings.ToLower(respBody)
	var found []string
	for _, pattern := range sensitiveResponsePatterns {
		if strings.Contains(lower, `"`+pattern+`"`) || strings.Contains(lower, `'`+pattern+`'`) {
			found = append(found, pattern)
		}
	}
	return found
}
