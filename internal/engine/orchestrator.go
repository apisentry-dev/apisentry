package engine

import (
	"github.com/apisentry/apisentry/internal/attacks"
	"github.com/apisentry/apisentry/internal/parser"
)

// AttackCase is a unified representation of any attack test
type AttackCase struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Description string
	Category    string // BOLA, BrokenAuth, MassAssignment, etc.
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW

	// Original typed test — used by executor to call the right Execute* func
	BOLATest       *attacks.BOLATest
	AuthTest       *attacks.BrokenAuthTest
	PropertyTest   *attacks.PropertyTest
	RateLimitTest  *attacks.RateLimitTest
	FuncAuthTest   *attacks.FuncAuthTest
	InjectionTest  *attacks.InjectionTest
	SSRFTest       *attacks.SSRFTest
	MisconfigTest  *attacks.MisconfigTest
	InventoryTest  *attacks.InventoryTest
}

// Plan holds all generated attack cases for a parsed API
type Plan struct {
	Endpoints     []parser.Endpoint
	Cases         []AttackCase
	TotalBOLA     int
	TotalAuth     int
	TotalProp     int
	TotalRate     int
	TotalFunc     int
	TotalInject    int
	TotalSSRF      int
	TotalMisconfig int
	TotalInventory int
}

// BuildPlan generates the full attack plan for all endpoints
func BuildPlan(endpoints []parser.Endpoint, baseURL string) Plan {
	plan := Plan{Endpoints: endpoints}

	// API1: BOLA
	for _, t := range attacks.GenerateBOLATests(endpoints, baseURL) {
		tc := t // capture
		plan.Cases = append(plan.Cases, AttackCase{
			Name:        tc.Name,
			Method:      tc.Method,
			URL:         tc.URL,
			Headers:     map[string]string{},
			Description: tc.Description,
			Category:    "BOLA (API1:2023)",
			Severity:    "HIGH",
			BOLATest:    &tc,
		})
		plan.TotalBOLA++
	}

	// API2: Broken Auth
	for _, t := range attacks.GenerateBrokenAuthTests(endpoints, baseURL) {
		tc := t
		plan.Cases = append(plan.Cases, AttackCase{
			Name:        tc.Name,
			Method:      tc.Method,
			URL:         tc.URL,
			Headers:     tc.Headers,
			Description: tc.Description,
			Category:    "Broken Auth (API2:2023)",
			Severity:    "CRITICAL",
			AuthTest:    &tc,
		})
		plan.TotalAuth++
	}

	// API3: Property (mass assignment + data exposure)
	for _, t := range attacks.GeneratePropertyTests(endpoints, baseURL) {
		tc := t
		sev := "HIGH"
		if tc.TestType == "mass_assignment" {
			sev = "HIGH"
		} else {
			sev = "MEDIUM"
		}
		plan.Cases = append(plan.Cases, AttackCase{
			Name:         tc.Name,
			Method:       tc.Method,
			URL:          tc.URL,
			Headers:      tc.Headers,
			Body:         tc.Body,
			Description:  tc.Description,
			Category:     "Mass Assignment / Data Exposure (API3:2023)",
			Severity:     sev,
			PropertyTest: &tc,
		})
		plan.TotalProp++
	}

	// API4: Rate Limiting
	for _, t := range attacks.GenerateRateLimitTests(endpoints, baseURL) {
		tc := t
		sev := "MEDIUM"
		if tc.TestType == "large_body" {
			sev = "LOW"
		}
		plan.Cases = append(plan.Cases, AttackCase{
			Name:          tc.Name,
			Method:        tc.Method,
			URL:           tc.URL,
			Headers:       tc.Headers,
			Body:          tc.Body,
			Description:   tc.Description,
			Category:      "Unrestricted Resource Consumption (API4:2023)",
			Severity:      sev,
			RateLimitTest: &tc,
		})
		plan.TotalRate++
	}

	// API5: Function Level Auth
	for _, t := range attacks.GenerateFuncAuthTests(endpoints, baseURL) {
		tc := t
		sev := "HIGH"
		if tc.TestType == "http_verb_tamper" {
			sev = "MEDIUM"
		}
		plan.Cases = append(plan.Cases, AttackCase{
			Name:         tc.Name,
			Method:       tc.Method,
			URL:          tc.URL,
			Headers:      tc.Headers,
			Description:  tc.Description,
			Category:     "Broken Function Auth (API5:2023)",
			Severity:     sev,
			FuncAuthTest: &tc,
		})
		plan.TotalFunc++
	}

	// API6+API10: Injection & Business Flow
	for _, t := range attacks.GenerateInjectionTests(endpoints, baseURL) {
		tc := t
		sev := "HIGH"
		if tc.TestType == "business_flow" {
			sev = "MEDIUM"
		}
		plan.Cases = append(plan.Cases, AttackCase{
			Name:          tc.Name,
			Method:        tc.Method,
			URL:           tc.URL,
			Headers:       tc.Headers,
			Body:          tc.Body,
			Description:   tc.Description,
			Category:      "Injection / Business Flow (API6:2023)",
			Severity:      sev,
			InjectionTest: &tc,
		})
		plan.TotalInject++
	}

	// API7: SSRF
	for _, t := range attacks.GenerateSSRFTests(endpoints, baseURL) {
		tc := t
		plan.Cases = append(plan.Cases, AttackCase{
			Name:        tc.Name,
			Method:      tc.Method,
			URL:         tc.URL,
			Headers:     tc.Headers,
			Body:        tc.Body,
			Description: tc.Description,
			Category:    "SSRF (API7:2023)",
			Severity:    "CRITICAL",
			SSRFTest:    &tc,
		})
		plan.TotalSSRF++
	}

	// API8: Security Misconfiguration
	for _, t := range attacks.GenerateMisconfigTests(endpoints, baseURL) {
		tc := t
		sev := "MEDIUM"
		if tc.TestType == "debug_endpoint" {
			sev = "HIGH"
		}
		plan.Cases = append(plan.Cases, AttackCase{
			Name:          tc.Name,
			Method:        tc.Method,
			URL:           tc.URL,
			Headers:       tc.Headers,
			Description:   tc.Description,
			Category:      "Security Misconfiguration (API8:2023)",
			Severity:      sev,
			MisconfigTest: &tc,
		})
		plan.TotalMisconfig++
	}

	// API9: Improper Inventory Management
	for _, t := range attacks.GenerateInventoryTests(endpoints, baseURL) {
		tc := t
		sev := "HIGH"
		if tc.TestType == "undoc_env" {
			sev = "MEDIUM"
		}
		plan.Cases = append(plan.Cases, AttackCase{
			Name:          tc.Name,
			Method:        tc.Method,
			URL:           tc.URL,
			Headers:       tc.Headers,
			Description:   tc.Description,
			Category:      "Improper Inventory Mgmt (API9:2023)",
			Severity:      sev,
			InventoryTest: &tc,
		})
		plan.TotalInventory++
	}

	return plan
}

// Deduplicate removes cases with same method+url+category
func (p *Plan) Deduplicate() {
	seen := map[string]bool{}
	var unique []AttackCase
	for _, c := range p.Cases {
		key := c.Method + "|" + c.URL + "|" + c.Category
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}
	p.Cases = unique
}
