package attacks

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apisentry-dev/apisentry/internal/parser"
)

// RateLimitTest represents a rate limiting / resource consumption test case
type RateLimitTest struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Description string
	TestType    string // "rate_limit", "large_body", "pagination_abuse"
}

// GenerateRateLimitTests generates resource consumption test cases
func GenerateRateLimitTests(endpoints []parser.Endpoint, baseURL string) []RateLimitTest {
	var tests []RateLimitTest

	for _, ep := range endpoints {
		url := buildEndpointURL(baseURL, ep.Path)

		// Rate limit burst test for all endpoints
		tests = append(tests, RateLimitTest{
			Name:        fmt.Sprintf("RATE_LIMIT_%s_%s", ep.Method, sanitizePath(ep.Path)),
			Method:      ep.Method,
			URL:         url,
			Headers:     map[string]string{},
			Description: fmt.Sprintf("Rate limit: send 20 rapid requests to %s %s, check for HTTP 429", ep.Method, ep.Path),
			TestType:    "rate_limit",
		})

		// Large body on POST/PUT/PATCH
		if ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH" {
			largeBody := `{"data":"` + strings.Repeat("A", 100*1024) + `"}` // 100KB
			tests = append(tests, RateLimitTest{
				Name:        fmt.Sprintf("LARGE_BODY_%s_%s", ep.Method, sanitizePath(ep.Path)),
				Method:      ep.Method,
				URL:         url,
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        largeBody,
				Description: fmt.Sprintf("Large body: send 100KB payload to %s %s", ep.Method, ep.Path),
				TestType:    "large_body",
			})
		}

		// Pagination abuse: request huge page on GET endpoints with pagination params
		if ep.Method == "GET" && hasPaginationParam(ep) {
			paginatedURL := addPaginationAbuse(url)
			tests = append(tests, RateLimitTest{
				Name:        fmt.Sprintf("PAGINATION_ABUSE_%s", sanitizePath(ep.Path)),
				Method:      "GET",
				URL:         paginatedURL,
				Headers:     map[string]string{},
				Description: fmt.Sprintf("Pagination abuse: GET %s with limit=999999 (resource exhaustion)", ep.Path),
				TestType:    "pagination_abuse",
			})
		}
	}

	return tests
}

func hasPaginationParam(ep parser.Endpoint) bool {
	for _, p := range ep.Parameters {
		lower := strings.ToLower(p.Name)
		if lower == "limit" || lower == "page_size" || lower == "per_page" || lower == "size" {
			return true
		}
	}
	return false
}

func addPaginationAbuse(url string) string {
	if strings.Contains(url, "?") {
		return url + "&limit=999999&page_size=999999"
	}
	return url + "?limit=999999&page_size=999999"
}

// RateLimitResult holds the outcome of a burst test
type RateLimitResult struct {
	TotalRequests int
	Responses     map[int]int // status code -> count
	Got429        bool
	Duration      time.Duration
}

// ExecuteRateLimitBurst sends N concurrent requests to test rate limiting
func ExecuteRateLimitBurst(test RateLimitTest, token string, count int) (RateLimitResult, error) {
	if count <= 0 {
		count = 20
	}

	result := RateLimitResult{
		TotalRequests: count,
		Responses:     map[int]int{},
	}

	var mu sync.Mutex
	var got429 int32
	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := doSingleRequest(test, token)
			mu.Lock()
			result.Responses[code]++
			mu.Unlock()
			if code == http.StatusTooManyRequests {
				atomic.StoreInt32(&got429, 1)
			}
		}()
	}

	wg.Wait()
	result.Duration = time.Since(start)
	result.Got429 = got429 == 1

	return result, nil
}

// ExecuteRateLimitTest sends a single request for large-body and pagination tests
func ExecuteRateLimitTest(test RateLimitTest, token string) (int, error) {
	return doSingleRequest(test, token)
}

func doSingleRequest(test RateLimitTest, token string) (int, error) {
	var bodyReader *strings.Reader
	if test.Body != "" {
		bodyReader = strings.NewReader(test.Body)
	} else {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequest(test.Method, test.URL, bodyReader)
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

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// IsRateLimitVulnerable returns true if none of the burst responses were 429
func IsRateLimitVulnerable(result RateLimitResult) bool {
	return !result.Got429 && result.TotalRequests >= 10
}
