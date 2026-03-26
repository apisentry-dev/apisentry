package scanner

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"
)

// Config holds scanner HTTP client configuration
type Config struct {
	Timeout     time.Duration
	RPS         int    // max requests per second (0 = unlimited)
	Token       string // Bearer token
	Insecure    bool   // skip TLS verification
	Concurrency int    // parallel workers
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Timeout:     10 * time.Second,
		RPS:         10,
		Concurrency: 5,
	}
}

// Response holds the result of a single HTTP request
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       string
	Latency    time.Duration
	Err        error
}

// Client is the APISentry HTTP client
type Client struct {
	cfg        Config
	httpClient *http.Client
	throttle   <-chan time.Time
}

// NewClient creates a Client from config
func NewClient(cfg Config) *Client {
	transport := &http.Transport{}

	c := &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
	}

	if cfg.RPS > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(cfg.RPS))
		c.throttle = ticker.C
	}

	return c
}

// Do sends a request and returns a Response
func (c *Client) Do(ctx context.Context, method, url string, headers map[string]string, body string) Response {
	// Rate limiting
	if c.throttle != nil {
		<-c.throttle
	}

	start := time.Now()

	var bodyReader *bytes.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return Response{Err: err}
	}

	req.Header.Set("User-Agent", "APISentry-Scanner/1.0")
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Response{Latency: time.Since(start), Err: err}
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	return Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       buf.String(),
		Latency:    time.Since(start),
	}
}

// sensitiveBodyPatterns are field names that should not appear in API responses
var sensitiveBodyPatterns = []string{
	`"password"`, `"passwd"`,
	`"ssn"`, `"social_security"`,
	`"credit_card"`, `"card_number"`, `"cvv"`,
	`"secret"`, `"private_key"`, `"api_key"`,
	`"refresh_token"`, `"access_token"`,
	`"pin"`, `"otp"`,
}

// FindSensitiveFields returns any sensitive field names found in a response body
func FindSensitiveFields(body string) []string {
	lower := strings.ToLower(body)
	var found []string
	for _, p := range sensitiveBodyPatterns {
		if strings.Contains(lower, p) {
			found = append(found, strings.Trim(p, `"`))
		}
	}
	return found
}
