package ai

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/apisentry-dev/apisentry/internal/scanner"
)

// AIAnalysis is the result of Claude analyzing a finding
type AIAnalysis struct {
	Verdict     string // "confirmed", "potential", "false_positive"
	Confidence  int    // 0-100
	Reasoning   string
	Remediation string
}

// Analyzer wraps the Anthropic Claude client
type Analyzer struct {
	client *anthropic.Client
	model  anthropic.Model
}

// NewAnalyzer creates an Analyzer. apiKey="" uses ANTHROPIC_API_KEY env var.
func NewAnalyzer(apiKey string) *Analyzer {
	var opts []option.RequestOption
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	client := anthropic.NewClient(opts...)
	return &Analyzer{
		client: &client,
		model:  anthropic.ModelClaudeHaiku4_5,
	}
}

// AnalyzeFinding sends a finding to Claude for classification
func (a *Analyzer) AnalyzeFinding(ctx context.Context, f scanner.Finding) (AIAnalysis, error) {
	systemPrompt := promptForCategory(f.Category)

	userMsg := fmt.Sprintf(
		"Finding:\nCategory: %s\nSeverity: %s\nEndpoint: %s %s\nDescription: %s\nEvidence: %s\nHTTP Status: %d",
		f.Category, f.Severity, f.Method, f.Endpoint, f.Description, f.Evidence, f.StatusCode,
	)

	msg, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: 512,
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
		},
	})
	if err != nil {
		return AIAnalysis{}, fmt.Errorf("claude API error: %w", err)
	}

	if len(msg.Content) == 0 {
		return AIAnalysis{}, fmt.Errorf("empty response from claude")
	}

	raw := msg.Content[0].Text
	return parseAnalysis(raw)
}

// AnalyzeFindings runs AI analysis on all findings, updating confidence scores
// Findings classified as false_positive are filtered out
func (a *Analyzer) AnalyzeFindings(ctx context.Context, findings []scanner.Finding) []scanner.Finding {
	var result []scanner.Finding

	for _, f := range findings {
		analysis, err := a.AnalyzeFinding(ctx, f)
		if err != nil {
			// On error: keep the finding as-is
			result = append(result, f)
			continue
		}

		if analysis.Verdict == "false_positive" {
			continue // drop
		}

		// Update confidence and add remediation to description
		f.Confidence = analysis.Confidence
		if analysis.Remediation != "" {
			f.Description = f.Description + " | Fix: " + analysis.Remediation
		}
		result = append(result, f)
	}

	return result
}

type rawAnalysis struct {
	Verdict     string `json:"verdict"`
	Confidence  int    `json:"confidence"`
	Reasoning   string `json:"reasoning"`
	Remediation string `json:"remediation"`
}

func parseAnalysis(raw string) (AIAnalysis, error) {
	// Find JSON in the response (Claude sometimes adds text around it)
	start := -1
	for i, c := range raw {
		if c == '{' {
			start = i
			break
		}
	}
	if start == -1 {
		return AIAnalysis{Verdict: "potential", Confidence: 50, Reasoning: raw}, nil
	}

	end := len(raw)
	for i := len(raw) - 1; i >= start; i-- {
		if raw[i] == '}' {
			end = i + 1
			break
		}
	}

	var r rawAnalysis
	if err := json.Unmarshal([]byte(raw[start:end]), &r); err != nil {
		return AIAnalysis{Verdict: "potential", Confidence: 50, Reasoning: raw}, nil
	}

	return AIAnalysis{
		Verdict:     r.Verdict,
		Confidence:  r.Confidence,
		Reasoning:   r.Reasoning,
		Remediation: r.Remediation,
	}, nil
}
