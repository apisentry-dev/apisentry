package attacks

import (
	"strings"
	"testing"

	"github.com/apisentry/apisentry/internal/parser"
)

func TestIsIDLike(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"id", true},
		{"userId", true},
		{"user_id", true},
		{"orderId", true},
		{"order_id", true},
		{"uuid", true},
		{"resourceUUID", true},
		{"name", false},
		{"status", false},
		{"page", false},
		{"limit", false},
		{"filter", false},
	}

	for _, tc := range cases {
		got := isIDLike(tc.name)
		if got != tc.want {
			t.Errorf("isIDLike(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSanitizePath(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/users/{userId}", "users_userId"},
		{"/orders/{orderId}/items", "orders_orderId_items"},
		{"/health", "health"},
		{"/{id}", "id"},
	}

	for _, tc := range cases {
		got := sanitizePath(tc.input)
		if got != tc.want {
			t.Errorf("sanitizePath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestBuildURL(t *testing.T) {
	cases := []struct {
		base      string
		path      string
		paramName string
		value     string
		want      string
	}{
		{"http://api.example.com", "/users/{userId}", "userId", "42", "http://api.example.com/users/42"},
		{"http://api.example.com/", "/orders/{orderId}", "orderId", "99", "http://api.example.com/orders/99"},
		{"http://localhost:8080", "/items/{id}", "id", "1", "http://localhost:8080/items/1"},
	}

	for _, tc := range cases {
		got := buildURL(tc.base, tc.path, tc.paramName, tc.value)
		if got != tc.want {
			t.Errorf("buildURL(%q, %q, %q, %q) = %q, want %q", tc.base, tc.path, tc.paramName, tc.value, got, tc.want)
		}
	}
}

func TestGenerateBOLATests_RequiresAuth(t *testing.T) {
	endpoints := []parser.Endpoint{
		{
			Method:       "GET",
			Path:         "/users/{userId}",
			RequiresAuth: true,
			Parameters: []parser.Parameter{
				{Name: "userId", In: "path", Type: "integer"},
			},
		},
		{
			Method:       "GET",
			Path:         "/users/{userId}/profile",
			RequiresAuth: false, // no auth — should be skipped
			Parameters: []parser.Parameter{
				{Name: "userId", In: "path", Type: "integer"},
			},
		},
	}

	tests := GenerateBOLATests(endpoints, "http://localhost:8080")

	// Only the auth-required endpoint should produce tests
	if len(tests) == 0 {
		t.Fatal("expected BOLA tests to be generated for auth-required endpoint")
	}

	// Non-auth endpoint must not generate any tests
	for _, tc := range tests {
		if strings.Contains(tc.URL, "profile") {
			t.Error("BOLA test generated for non-auth endpoint — should be skipped")
		}
	}
}

func TestGenerateBOLATests_AlternativeIDs(t *testing.T) {
	endpoints := []parser.Endpoint{
		{
			Method:       "GET",
			Path:         "/orders/{orderId}",
			RequiresAuth: true,
			Parameters: []parser.Parameter{
				{Name: "orderId", In: "path", Type: "integer"},
			},
		},
	}

	tests := GenerateBOLATests(endpoints, "http://localhost:8080")

	// Should generate one test per alternativeID
	if len(tests) != len(alternativeIDs) {
		t.Errorf("expected %d BOLA tests (one per alternative ID), got %d", len(alternativeIDs), len(tests))
	}

	// All tests should have the endpoint's method
	for _, tc := range tests {
		if tc.Method != "GET" {
			t.Errorf("expected method GET, got %s", tc.Method)
		}
		if !strings.Contains(tc.URL, "http://localhost:8080/orders/") {
			t.Errorf("URL %q does not contain expected base path", tc.URL)
		}
	}
}

func TestGenerateBOLATests_NonIDParam(t *testing.T) {
	endpoints := []parser.Endpoint{
		{
			Method:       "GET",
			Path:         "/search",
			RequiresAuth: true,
			Parameters: []parser.Parameter{
				{Name: "query", In: "query", Type: "string"},
				{Name: "page", In: "query", Type: "integer"},
			},
		},
	}

	tests := GenerateBOLATests(endpoints, "http://localhost:8080")

	if len(tests) != 0 {
		t.Errorf("expected 0 BOLA tests for endpoint with no path ID params, got %d", len(tests))
	}
}
