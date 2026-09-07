package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/collector"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/detector"
	"github.com/whiteclover0542/secrethound/internal/filter"
	"github.com/whiteclover0542/secrethound/internal/finding"
	"github.com/whiteclover0542/secrethound/internal/reporter"
)

var version = "dev"

// CI가 "시크릿 탐지"와 "실행 실패"를 구분할 수 있도록 종료 코드를 나눈다.
const (
	exitFindings = 1
	exitError    = 2

	formatText = "text"
	formatJSON = "json"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(exitError)
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
	var (
		rulesPath  string
		format     string
		outputPath string
		noColor    bool
		useExit    bool
		history    bool
		maxCommits int
	)

	cmd := &cobra.Command{
		Use:           "scan [path]",
		Short:         "지정한 경로를 스캔한다",
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != formatText && format != formatJSON {
				return fmt.Errorf("지원하지 않는 출력 형식: %s (text 또는 json)", format)
			}

			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			started := time.Now()
			rs, err := loadRuleset(rulesPath)
			if err != nil {
				return err
			}

			det := detector.New(rs.Rules)
			col := collector.New(&rs.Filter)
			var findings []finding.Finding

			stats, err := col.WalkTree(target, func(s collector.Source) error {
				findings = append(findings, det.Scan(detector.Location{Path: s.Path}, s.Content)...)
				return nil
			})
			if err != nil {
				return err
			}

			var histStats collector.HistoryStats
			if history {
				histStats, err = col.WalkHistory(target,
					collector.HistoryOptions{MaxCommits: maxCommits},
					func(ch collector.Change) error {
						loc := detector.Location{
							Path:   ch.Path,
							Commit: ch.Commit,
							Author: ch.Author,
							Date:   ch.Date,
						}
						findings = append(findings, det.ScanLine(loc, ch.Line, ch.LineNo)...)
						return nil
					})
				if err != nil {
					return err
				}
			}

			fp, err := filter.New(&rs.Filter)
			if err != nil {
				return err
			}
			findings, fpStats := fp.Apply(findings)

			report := reporter.Build(reporter.Input{
				Target:         target,
				Version:        version,
				Findings:       findings,
				FilesScanned:   stats.Scanned,
				FilesSkipped:   stats.Skipped,
				CommitsScanned: histStats.Commits,
				FilteredOut:    fpStats.Filtered + fpStats.Allowlist,
				Duration:       time.Since(started),
			})

			out := os.Stdout
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("결과 파일 생성 실패: %w", err)
				}
				defer f.Close()
				out = f
			}

			if format == formatJSON {
				err = reporter.WriteJSON(out, report)
			} else {
				err = reporter.WriteText(out, report, !noColor && reporter.IsTerminal(out))
			}
			if err != nil {
				return err
			}

			if useExit && len(findings) > 0 {
				os.Exit(exitFindings)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&rulesPath, "rules", "r", "", "룰셋 파일 경로 (기본: 내장 룰셋)")
	cmd.Flags().StringVarP(&format, "format", "f", formatText, "출력 형식 (text | json)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "결과를 파일로 저장 (기본: 표준 출력)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "색상 출력 비활성화")
	cmd.Flags().BoolVar(&useExit, "exit-code", true, "시크릿 탐지 시 종료 코드 1 반환 (CI 연동용)")
	cmd.Flags().BoolVar(&history, "history", false, "git 커밋 히스토리까지 스캔 (과거에 지운 시크릿 탐지)")
	cmd.Flags().IntVar(&maxCommits, "max-commits", 0, "히스토리 스캔 대상 커밋 수 제한 (0 = 전체)")
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
