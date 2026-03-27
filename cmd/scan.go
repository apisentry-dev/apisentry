package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/apisentry-dev/apisentry/internal/ai"
	"github.com/apisentry-dev/apisentry/internal/engine"
	"github.com/apisentry-dev/apisentry/internal/parser"
	"github.com/apisentry-dev/apisentry/internal/report"
	"github.com/apisentry-dev/apisentry/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	specFile    string
	targetURL   string
	token       string
	dryRun      bool
	format      string
	outputFile  string
	aiAnalyze   bool
	concurrency int
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan an API for security vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("╔══════════════════════════════════════╗\n")
		fmt.Printf("║       APISentry Security Scanner     ║\n")
		fmt.Printf("╚══════════════════════════════════════╝\n\n")
		fmt.Printf("  Spec:   %s\n", specFile)
		fmt.Printf("  Target: %s\n", targetURL)
		mode := "active scan"
		if dryRun {
			mode = "dry-run (no requests)"
		}
		if aiAnalyze {
			mode += " + AI analysis"
		}
		fmt.Printf("  Mode:   %s\n\n", mode)

		// 1. Parse spec
		endpoints, err := parser.ParseSpec(specFile)
		if err != nil {
			return fmt.Errorf("failed to parse spec: %w", err)
		}
		fmt.Printf("✓ Parsed %d endpoints\n", len(endpoints))

		// 2. Build attack plan
		plan := engine.BuildPlan(endpoints, targetURL)
		plan.Deduplicate()
		fmt.Printf("✓ Generated %d attack tests (BOLA: %d, Auth: %d, Property: %d, RateLimit: %d, FuncAuth: %d, Injection: %d, SSRF: %d, Misconfig: %d, Inventory: %d)\n\n",
			len(plan.Cases), plan.TotalBOLA, plan.TotalAuth, plan.TotalProp, plan.TotalRate, plan.TotalFunc,
			plan.TotalInject, plan.TotalSSRF, plan.TotalMisconfig, plan.TotalInventory)

		if dryRun {
			fmt.Println("Dry-run mode — no requests sent.")
			return nil
		}

		// 3. Execute scan
		cfg := scanner.DefaultConfig()
		cfg.Token = token
		cfg.Concurrency = concurrency

		fmt.Println("Scanning...")
		result := scanner.Execute(context.Background(), plan, cfg)
		result.Target = targetURL
		result.SpecFile = specFile

		// 4. AI analysis (optional)
		if aiAnalyze && len(result.Findings) > 0 {
			fmt.Printf("Running AI analysis on %d findings...\n", len(result.Findings))
			apiKey := os.Getenv("ANTHROPIC_API_KEY")
			analyzer := ai.NewAnalyzer(apiKey)
			before := len(result.Findings)
			result.Findings = analyzer.AnalyzeFindings(context.Background(), result.Findings)
			fmt.Printf("✓ AI filtered: %d → %d findings (removed %d false positives)\n\n",
				before, len(result.Findings), before-len(result.Findings))
		}

		// 5. Output report
		return report.Generate(result, format, outputFile)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&specFile, "spec", "s", "", "Path to OpenAPI spec file (required)")
	scanCmd.Flags().StringVarP(&targetURL, "target", "t", "", "Target API base URL (required)")
	scanCmd.Flags().StringVar(&token, "token", "", "Bearer token for authenticated requests")
	scanCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Generate attack plan without sending requests")
	scanCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text|json|html|sarif")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write report to file instead of stdout")
	scanCmd.Flags().BoolVar(&aiAnalyze, "ai", false, "Enable AI analysis of findings (requires ANTHROPIC_API_KEY)")
	scanCmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of parallel HTTP workers")
	scanCmd.MarkFlagRequired("spec")
	scanCmd.MarkFlagRequired("target")
}
