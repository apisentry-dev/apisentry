package parser

import (
	"context"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
)

// Parameter represents an API parameter (path, query, header, cookie)
type Parameter struct {
	Name     string
	In       string // path, query, header, cookie
	Required bool
	Type     string
}

// RequestBody represents a request body schema
type RequestBody struct {
	ContentType string
	Properties  []string
}

// Endpoint represents a parsed API endpoint
type Endpoint struct {
	Method      string
	Path        string
	OperationID string
	Parameters  []Parameter
	RequestBody *RequestBody
	Tags        []string
	RequiresAuth bool
}

// ParseSpec loads and parses an OpenAPI 3.x spec file, returning all endpoints
func ParseSpec(specPath string) ([]Endpoint, error) {
	loader := openapi3.NewLoader()

	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load spec file %q: %w", specPath, err)
	}

	if err := doc.Validate(context.Background()); err != nil {
		// Non-fatal: log warning but continue
		fmt.Printf("  Warning: spec validation issues: %v\n", err)
	}

	var endpoints []Endpoint

	for path, pathItem := range doc.Paths.Map() {
		ops := map[string]*openapi3.Operation{
			"GET":    pathItem.Get,
			"POST":   pathItem.Post,
			"PUT":    pathItem.Put,
			"PATCH":  pathItem.Patch,
			"DELETE": pathItem.Delete,
		}

		for method, op := range ops {
			if op == nil {
				continue
			}

			ep := Endpoint{
				Method:      method,
				Path:        path,
				OperationID: op.OperationID,
				Tags:        op.Tags,
			}

			// Parse parameters
			for _, paramRef := range op.Parameters {
				if paramRef.Value == nil {
					continue
				}
				p := paramRef.Value
				param := Parameter{
					Name:     p.Name,
					In:       p.In,
					Required: p.Required,
				}
				if p.Schema != nil && p.Schema.Value != nil {
					param.Type = extractType(p.Schema.Value)
				}
				ep.Parameters = append(ep.Parameters, param)
			}

			// Parse request body
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				rb := &RequestBody{}
				for contentType, mediaType := range op.RequestBody.Value.Content {
					rb.ContentType = contentType
					if mediaType.Schema != nil && mediaType.Schema.Value != nil {
						for propName := range mediaType.Schema.Value.Properties {
							rb.Properties = append(rb.Properties, propName)
						}
					}
					break // take first content type
				}
				ep.RequestBody = rb
			}

			// Detect if auth is required
			ep.RequiresAuth = requiresAuth(op)

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints, nil
}

// extractType safely extracts a type string from a schema,
// handling allOf/oneOf/anyOf and empty type slices.
func extractType(schema *openapi3.Schema) string {
	if schema == nil {
		return "unknown"
	}
	types := schema.Type.Slice()
	if len(types) > 0 {
		return types[0]
	}
	// allOf/oneOf/anyOf — try first sub-schema
	if len(schema.AllOf) > 0 && schema.AllOf[0].Value != nil {
		return extractType(schema.AllOf[0].Value)
	}
	if len(schema.OneOf) > 0 && schema.OneOf[0].Value != nil {
		return extractType(schema.OneOf[0].Value)
	}
	if len(schema.AnyOf) > 0 && schema.AnyOf[0].Value != nil {
		return extractType(schema.AnyOf[0].Value)
	}
	return "object"
}

// requiresAuth checks if an operation requires authentication
func requiresAuth(op *openapi3.Operation) bool {
	if op.Security == nil {
		return false
	}
	for _, req := range *op.Security {
		if len(req) > 0 {
			return true
		}
	}
	return false
}
