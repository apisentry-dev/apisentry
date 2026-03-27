package engine

import (
	"strings"
	"testing"

	"github.com/apisentry/apisentry/internal/parser"
)

func makeAuthEndpointWithID() parser.Endpoint {
	return parser.Endpoint{
		Method:       "GET",
		Path:         "/orders/{orderId}",
		RequiresAuth: true,
		Parameters: []parser.Parameter{
			{Name: "orderId", In: "path", Type: "integer"},
		},
	}
}

func makeAuthEndpoint() parser.Endpoint {
	return parser.Endpoint{
		Method:       "GET",
		Path:         "/api/profile",
		RequiresAuth: true,
	}
}

func makePublicEndpoint() parser.Endpoint {
	return parser.Endpoint{
		Method:       "GET",
		Path:         "/api/health",
		RequiresAuth: false,
	}
}

func TestBuildPlan_ReturnsPlan(t *testing.T) {
	endpoints := []parser.Endpoint{
		makeAuthEndpointWithID(),
		makeAuthEndpoint(),
		makePublicEndpoint(),
	}

	plan := BuildPlan(endpoints, "http://localhost:8080")

	if len(plan.Cases) == 0 {
		t.Fatal("expected attack cases to be generated, got 0")
	}

	if len(plan.Endpoints) != 3 {
		t.Errorf("expected 3 endpoints in plan, got %d", len(plan.Endpoints))
	}
}

func TestBuildPlan_BOLAOnlyForAuthEndpoints(t *testing.T) {
	endpoints := []parser.Endpoint{
		makeAuthEndpointWithID(),
		{
			Method:       "GET",
			Path:         "/public/{itemId}",
			RequiresAuth: false,
			Parameters: []parser.Parameter{
				{Name: "itemId", In: "path", Type: "integer"},
			},
		},
	}

	plan := BuildPlan(endpoints, "http://localhost:8080")

	for _, c := range plan.Cases {
		if strings.Contains(c.Category, "BOLA") && strings.Contains(c.URL, "/public/") {
			t.Error("BOLA test generated for non-auth endpoint")
		}
	}

	if plan.TotalBOLA == 0 {
		t.Error("expected BOLA tests to be generated for auth-required endpoint with ID param")
	}
}

func TestBuildPlan_Counters(t *testing.T) {
	endpoints := []parser.Endpoint{
		makeAuthEndpointWithID(),
		makeAuthEndpoint(),
	}

	plan := BuildPlan(endpoints, "http://localhost:8080")

	// Verify counters match actual case counts by checking typed test pointers
	var bolaCount, authCount int
	for _, c := range plan.Cases {
		if c.BOLATest != nil {
			bolaCount++
		}
		if c.AuthTest != nil {
			authCount++
		}
	}

	if plan.TotalBOLA != bolaCount {
		t.Errorf("TotalBOLA = %d, but counted %d BOLA cases", plan.TotalBOLA, bolaCount)
	}
	if plan.TotalAuth != authCount {
		t.Errorf("TotalAuth = %d, but counted %d auth cases", plan.TotalAuth, authCount)
	}
}

func TestPlanDeduplicate(t *testing.T) {
	plan := Plan{
		Cases: []AttackCase{
			{Method: "GET", URL: "http://api/users/1", Category: "BOLA"},
			{Method: "GET", URL: "http://api/users/1", Category: "BOLA"}, // duplicate
			{Method: "GET", URL: "http://api/users/2", Category: "BOLA"}, // different URL
			{Method: "POST", URL: "http://api/users/1", Category: "BOLA"}, // different method
		},
	}

	plan.Deduplicate()

	if len(plan.Cases) != 3 {
		t.Errorf("after dedup expected 3 unique cases, got %d", len(plan.Cases))
	}
}

func TestPlanDeduplicate_Empty(t *testing.T) {
	plan := Plan{}
	plan.Deduplicate()
	if len(plan.Cases) != 0 {
		t.Error("deduplicate of empty plan should stay empty")
	}
}

func TestBuildPlan_AllCategoriesPresent(t *testing.T) {
	endpoints := []parser.Endpoint{
		makeAuthEndpointWithID(),
		makePublicEndpoint(),
	}

	plan := BuildPlan(endpoints, "http://localhost:8080")

	// Misconfig and Inventory tests are generated regardless of auth
	if plan.TotalMisconfig == 0 {
		t.Error("expected misconfig tests to be generated")
	}
	if plan.TotalInventory == 0 {
		t.Error("expected inventory tests to be generated")
	}
}
