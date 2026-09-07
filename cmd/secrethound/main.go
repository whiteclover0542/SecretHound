package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/reporter"
	"github.com/whiteclover0542/secrethound/internal/scanner"
	"github.com/whiteclover0542/secrethound/internal/validator"
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
		rulesPath   string
		format      string
		outputPath  string
		noColor     bool
		useExit     bool
		history     bool
		maxCommits  int
		reportPath  string
		validate    bool
		validateTTL time.Duration
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

			result, err := scanner.Run(cmd.Context(), rs, scanner.Options{
				Target:     target,
				History:    history,
				MaxCommits: maxCommits,
				Validate: scanner.ValidateOptions{
					Enabled: validate,
					Timeout: validateTTL,
				},
			})
			if err != nil {
				return err
			}

			report := reporter.Build(reporter.Input{
				Target:         target,
				Version:        version,
				Findings:       result.Findings,
				FilesScanned:   result.FilesScanned,
				FilesSkipped:   result.FilesSkipped,
				CommitsScanned: result.CommitsScanned,
				FilteredOut:    result.FilteredOut,
				Validated:      result.Validated,
				Validation:     result.Validation,
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

			// CI는 사람이 읽는 로그와 기계가 읽는 결과를 동시에 필요로 한다.
			// 스캔을 두 번 돌리지 않도록 리포트를 별도 파일로도 남긴다.
			if reportPath != "" {
				if err := writeReportFile(reportPath, report); err != nil {
					return err
				}
			}

			if useExit && len(result.Findings) > 0 {
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
	cmd.Flags().StringVar(&reportPath, "report", "", "일반 출력과 별개로 JSON 리포트를 저장할 경로")
	// 탐지한 자격증명을 발급처로 내보내는 기능이라 기본값은 반드시 false여야 한다.
	// 사용자가 스캔 대상 레포의 키를 외부로 보내도 되는지 판단할 기회를 뺏으면 안 된다.
	cmd.Flags().BoolVar(&validate, "validate", false,
		"탐지한 키가 살아있는지 발급처 API에 확인 (네트워크 사용, 기본 비활성)")
	cmd.Flags().DurationVar(&validateTTL, "validate-timeout", 5*time.Second,
		"검증 요청 하나당 제한 시간")
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
			// 어떤 룰이 --validate 대상인지 미리 알 수 있어야
			// 사용자가 검증을 켤 가치가 있는지 판단할 수 있다.
			supported := validator.SupportedRules()

			validatable := 0
			for _, r := range rs.Rules {
				mark := ""
				if provider, ok := supported[r.ID]; ok {
					mark = "검증: " + provider
					validatable++
				}
				fmt.Printf("%-28s %-9s %-16s %s\n", r.ID, r.Severity, mark, r.Description)
			}
			fmt.Printf("\n총 %d개 룰 (그중 %d개는 --validate 로 생존 확인 가능)\n",
				len(rs.Rules), validatable)
			return nil
		},
	}
	cmd.Flags().StringVarP(&rulesPath, "rules", "r", "", "룰셋 파일 경로 (기본: 내장 룰셋)")
	return cmd
}

func writeReportFile(path string, report reporter.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("리포트 파일 생성 실패: %w", err)
	}
	defer f.Close()

	if err := reporter.WriteJSON(f, report); err != nil {
		return fmt.Errorf("리포트 저장 실패: %w", err)
	}
	return nil
}

func loadRuleset(path string) (*config.Ruleset, error) {
	if path != "" {
		return config.Load(path)
	}
	return config.Parse(secrethound.DefaultRuleset)
}
