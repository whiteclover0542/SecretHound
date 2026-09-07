package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/collector"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/detector"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secrethound",
		Short:   "Git 레포에서 유출된 API 키와 시크릿을 탐지하는 도구",
		Version: version,
	}
	cmd.AddCommand(scanCmd(), rulesCmd())
	return cmd
}

func scanCmd() *cobra.Command {
	var rulesPath string

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "지정한 경로를 스캔한다",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}
			rs, err := loadRuleset(rulesPath)
			if err != nil {
				return err
			}

			det := detector.New(rs.Rules)
			var findings []finding.Finding

			c := collector.New(&rs.Filter)
			stats, err := c.WalkTree(target, func(s collector.Source) error {
				findings = append(findings, det.Scan(s.Path, s.Commit, s.Content)...)
				return nil
			})
			if err != nil {
				return err
			}

			// TODO: FP Filter / Reporter 연결
			for _, f := range findings {
				fmt.Printf("[%s] %s:%d  %s  %s\n", f.Severity, f.Path, f.Line, f.RuleID, f.Masked)
			}

			fmt.Printf("\n파일 %d개 스캔 (제외 %d개), 탐지 %d건\n",
				stats.Scanned, stats.Skipped, len(findings))

			if len(findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&rulesPath, "rules", "r", "", "룰셋 파일 경로 (기본: 내장 룰셋)")
	return cmd
}

func rulesCmd() *cobra.Command {
	var rulesPath string

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "로드된 탐지 룰 목록을 출력한다",
		RunE: func(cmd *cobra.Command, args []string) error {
			rs, err := loadRuleset(rulesPath)
			if err != nil {
				return err
			}
			for _, r := range rs.Rules {
				fmt.Printf("%-28s %-9s %s\n", r.ID, r.Severity, r.Description)
			}
			fmt.Printf("\n총 %d개 룰\n", len(rs.Rules))
			return nil
		},
	}
	cmd.Flags().StringVarP(&rulesPath, "rules", "r", "", "룰셋 파일 경로 (기본: 내장 룰셋)")
	return cmd
}

func loadRuleset(path string) (*config.Ruleset, error) {
	if path != "" {
		return config.Load(path)
	}
	return config.Parse(secrethound.DefaultRuleset)
}
