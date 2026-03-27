package scanner

import (
	"testing"
	"time"
)

func TestFindSensitiveFields_Found(t *testing.T) {
	body := `{"id": 1, "email": "user@example.com", "password": "secret123", "credit_card": "4111111111111111"}`
	found := FindSensitiveFields(body)

	if len(found) == 0 {
		t.Fatal("expected sensitive fields to be found")
	}

	has := func(field string) bool {
		for _, f := range found {
			if f == field {
				return true
			}
		}
		return false
	}

	if !has("password") {
		t.Error("expected 'password' to be detected")
	}
	if !has("credit_card") {
		t.Error("expected 'credit_card' to be detected")
	}
}

func TestFindSensitiveFields_Clean(t *testing.T) {
	body := `{"id": 1, "email": "user@example.com", "username": "john", "status": "active"}`
	found := FindSensitiveFields(body)

	if len(found) != 0 {
		t.Errorf("expected no sensitive fields in clean response, got %v", found)
	}
}

func TestFindSensitiveFields_CaseInsensitive(t *testing.T) {
	body := `{"PASSWORD": "secret", "API_KEY": "abc123"}`
	found := FindSensitiveFields(body)

	// password and api_key are matched case-insensitively
	if len(found) == 0 {
		t.Error("expected sensitive fields found case-insensitively")
	}
}

func TestFindSensitiveFields_Empty(t *testing.T) {
	found := FindSensitiveFields("")
	if len(found) != 0 {
		t.Errorf("expected no findings for empty body, got %v", found)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %s", cfg.Timeout)
	}
	if cfg.Concurrency != 5 {
		t.Errorf("expected default concurrency 5, got %d", cfg.Concurrency)
	}
	if cfg.RPS != 10 {
		t.Errorf("expected default RPS 10, got %d", cfg.RPS)
	}
}

func TestNewClient_NotNil(t *testing.T) {
	cfg := DefaultConfig()
	client := NewClient(cfg)
	if client == nil {
		t.Error("NewClient returned nil")
	}
}
