package attacks

import (
	"strings"
	"testing"

	"github.com/apisentry/apisentry/internal/parser"
)

func TestBuildEndpointURL(t *testing.T) {
	cases := []struct {
		base string
		path string
		want string
	}{
		{"http://api.example.com", "/users/{userId}", "http://api.example.com/users/1"},
		{"http://api.example.com/", "/orders/{orderId}/items/{itemId}", "http://api.example.com/orders/1/items/1"},
		{"http://localhost:8080", "/health", "http://localhost:8080/health"},
	}

	for _, tc := range cases {
		got := buildEndpointURL(tc.base, tc.path)
		if got != tc.want {
			t.Errorf("buildEndpointURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}

func TestIsBrokenAuthVulnerable(t *testing.T) {
	cases := []struct {
		statusCode int
		want       bool
	}{
		{200, true},
		{201, true},
		{204, true},
		{299, true},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{500, false},
	}

	for _, tc := range cases {
		got := IsBrokenAuthVulnerable(tc.statusCode)
		if got != tc.want {
			t.Errorf("IsBrokenAuthVulnerable(%d) = %v, want %v", tc.statusCode, got, tc.want)
		}
	}
}

func TestGenerateBrokenAuthTests_AuthRequired(t *testing.T) {
	endpoints := []parser.Endpoint{
		{
			Method:       "GET",
			Path:         "/api/orders",
			RequiresAuth: true,
		},
		{
			Method:       "GET",
			Path:         "/api/public",
			RequiresAuth: false,
		},
	}

	tests := GenerateBrokenAuthTests(endpoints, "http://localhost:8080")

	if len(tests) == 0 {
		t.Fatal("expected auth tests to be generated for auth-required endpoint")
	}

	// Non-auth endpoint should not produce no_auth tests
	for _, tc := range tests {
		if strings.Contains(tc.URL, "/api/public") && tc.TestType == "no_auth" {
			t.Error("no_auth test generated for non-auth endpoint")
		}
	}
}

func TestGenerateBrokenAuthTests_TestTypes(t *testing.T) {
	endpoints := []parser.Endpoint{
		{
			Method:       "POST",
			Path:         "/api/login",
			RequiresAuth: true,
		},
	}

	tests := GenerateBrokenAuthTests(endpoints, "http://localhost:8080")

	// Should have 1 no_auth + len(invalidTokens) invalid token tests
	expectedCount := 1 + len(invalidTokens)
	if len(tests) != expectedCount {
		t.Errorf("expected %d tests (1 no_auth + %d invalid tokens), got %d", expectedCount, len(invalidTokens), len(tests))
	}

	// Verify at least one no_auth test
	hasNoAuth := false
	for _, tc := range tests {
		if tc.TestType == "no_auth" {
			hasNoAuth = true
			if len(tc.Headers) != 0 {
				t.Error("no_auth test should have empty headers")
			}
		}
	}
	if !hasNoAuth {
		t.Error("no no_auth test found")
	}

	// Verify invalid token tests have Authorization header
	for _, tc := range tests {
		if tc.TestType == "invalid_token" {
			if _, ok := tc.Headers["Authorization"]; !ok {
				t.Error("invalid_token test missing Authorization header")
			}
		}
	}
}

func TestGenerateBrokenAuthTests_NoAuthEndpoints(t *testing.T) {
	endpoints := []parser.Endpoint{
		{
			Method:       "GET",
			Path:         "/api/public/status",
			RequiresAuth: false,
		},
	}

	tests := GenerateBrokenAuthTests(endpoints, "http://localhost:8080")

	if len(tests) != 0 {
		t.Errorf("expected 0 tests for non-auth endpoints, got %d", len(tests))
	}
}
