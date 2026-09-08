package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/baseline"
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
	formatMD   = "md"
	formatHTML = "html"

	// --open 으로 저장할 때 쓰는 기본 파일 이름 (확장자는 형식에 따라 붙는다).
	defaultReportName = "secrethound-report"
)

// formatExt는 지원하는 출력 형식과 그 파일 확장자다.
// 이 맵의 키가 곧 --format 이 받을 수 있는 값의 전부다.
var formatExt = map[string]string{
	formatText: ".txt",
	formatJSON: ".json",
	formatMD:   ".md",
	formatHTML: ".html",
}

// findingsExit는 "시크릿을 찾았다"는 종료 코드를 main까지 전달한다.
//
// 커맨드 안에서 os.Exit을 부르면 콘솔 코드페이지를 되돌리거나 더블클릭 창을 붙잡는
// 마무리 작업을 건너뛰게 되므로, 종료는 main 한 곳에서만 한다.
var findingsExit bool

func main() {
	// 콘솔은 사용자 것이라 빌려 쓰는 셈이다. 끝나면 되돌린다.
	restoreConsole := setupConsole()

	// 탐색기에서 더블클릭했거나 폴더를 끌어다 놓았으면 커맨드를 대신 채워준다.
	args, fromExplorer := explorerLaunch(os.Args[1:])

	cmd := rootCmd()
	cmd.SetArgs(args)
	err := cmd.Execute()

	if fromExplorer {
		// 더블클릭으로 열린 창은 프로그램이 끝나는 순간 사라진다. 결과를 읽을
		// 시간을 준다.
		waitForKey()
	}
	restoreConsole()

	switch {
	case err != nil:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(exitError)
	case findingsExit:
		os.Exit(exitFindings)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secrethound",
		Short:   "Git 레포에서 유출된 API 키와 시크릿을 탐지하는 도구",
		Version: version,
	}
	cmd.AddCommand(checkCmd(), scanCmd(), rulesCmd(), selfcheckCmd())
	return cmd
}

func selfcheckCmd() *cobra.Command {
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "selfcheck",
		Short: "검증기가 아직 정상인지 확인한다 (실제 자격증명 불필요)",
		Long: `각 발급처에 형식만 맞는 가짜 키를 보내, 인증 거부 응답의 형태가
알고 있는 것과 같은지 확인한다.

검증기의 가장 위험한 고장은 조용하다. 요청이 잘못 만들어져 있으면 발급처는
살아있는 키에도 401을 주고, 리포트에는 "폐기됨"이 찍힌다. 죽은 키가 나오는 것은
정상적인 결과처럼 보이므로 아무도 이상함을 느끼지 못한다.

성공 경로(살아있는 키 → 유효)는 이 명령으로 확인되지 않는다. 진짜 키가 필요하다.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			results := validator.New(validator.Options{Timeout: timeout}).
				SelfCheck(cmd.Context())

			var failed, unverified int
			for _, r := range results {
				switch {
				case r.Err != "":
					fmt.Printf("[오류]   %-16s %s\n", r.Label, r.Err)
					failed++
				case !r.HasSignature:
					fmt.Printf("[미확인] %-16s HTTP %d → %s | %s\n",
						r.Label, r.Code, r.Status, r.Excerpt)
					unverified++
				case r.OK:
					fmt.Printf("[정상]   %-16s HTTP %d → %s\n", r.Label, r.Code, r.Status)
				default:
					fmt.Printf("[불일치] %-16s HTTP %d → %s (%s) | %s\n",
						r.Label, r.Code, r.Status, r.Reason, r.Excerpt)
					failed++
				}
			}

			fmt.Printf("\n발급처 %d곳 — 정상 %d, 불일치·오류 %d, 형식 미확인 %d\n",
				len(results), len(results)-failed-unverified, failed, unverified)

			if unverified > 0 {
				fmt.Println("미확인 항목은 위 응답을 보고 checks.go 의 revoked 시그니처를 채우면 된다.")
			}
			if failed > 0 {
				return fmt.Errorf("검증기 %d곳이 예상과 다르게 동작한다", failed)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "요청 하나당 제한 시간")
	return cmd
}

func scanCmd() *cobra.Command {
	var (
		rulesPath       string
		format          string
		outputPath      string
		noColor         bool
		useExit         bool
		history         bool
		maxCommits      int
		reportPath      string
		validate        bool
		validateTTL     time.Duration
		baselinePath    string
		baselineOutPath string
		workers         int
		openReport      bool
	)

	cmd := &cobra.Command{
		Use:           "scan [path]",
		Short:         "지정한 경로를 스캔한다",
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ext, ok := formatExt[format]
			if !ok {
				return fmt.Errorf("지원하지 않는 출력 형식: %s (text, json, md, html 중 하나)", format)
			}
			if baselinePath != "" && baselineOutPath != "" {
				return fmt.Errorf("--baseline 과 --baseline-out 은 함께 쓸 수 없습니다")
			}

			// --open 은 열어 볼 파일이 있어야 성립한다. 저장 위치를 따로 주지
			// 않았으면 현재 폴더에 기본 이름으로 만든다.
			if openReport && outputPath == "" {
				outputPath = defaultReportName + ext
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

			var bl *baseline.Baseline
			if baselinePath != "" {
				bl, err = baseline.Load(baselinePath)
				if err != nil {
					return fmt.Errorf("%w (먼저 --baseline-out 으로 baseline을 만드세요)", err)
				}
			}

			result, err := scanner.Run(cmd.Context(), rs, scanner.Options{
				Target:     target,
				History:    history,
				MaxCommits: maxCommits,
				Baseline:   bl,
				Workers:    workers,
				Validate: scanner.ValidateOptions{
					Enabled: validate,
					Timeout: validateTTL,
				},
			})
			if err != nil {
				return err
			}

			if baselineOutPath != "" {
				if err := baseline.Save(baselineOutPath, result.Findings); err != nil {
					return fmt.Errorf("baseline 저장 실패: %w", err)
				}
				// 리포트 내용(stdout)과 섞이면 --format json 을 리다이렉트해 쓰는
				// 파이프라인이 깨지므로 상태 메시지는 stderr로 보낸다.
				fmt.Fprintf(os.Stderr, "baseline 저장됨: %s (%d건)\n", baselineOutPath, len(result.Findings))
			}

			report := reporter.Build(reporter.Input{
				Target:         target,
				Version:        version,
				Findings:       result.Findings,
				FilesScanned:   result.FilesScanned,
				FilesSkipped:   result.FilesSkipped,
				CommitsScanned: result.CommitsScanned,
				FilteredOut:    result.FilteredOut,
				BaselineKnown:  result.BaselineKnown,
				Validated:      result.Validated,
				Validation:     result.Validation,
				Duration:       time.Since(started),
			})

			if err := emitReport(report, format, outputPath, !noColor); err != nil {
				return err
			}

			// CI는 사람이 읽는 로그와 기계가 읽는 결과를 동시에 필요로 한다.
			// 스캔을 두 번 돌리지 않도록 리포트를 별도 파일로도 남긴다.
			if reportPath != "" {
				if err := writeReportFile(reportPath, report); err != nil {
					return err
				}
			}

			if openReport {
				// 브라우저를 못 열었다고 스캔 결과가 달라지지는 않는다.
				// 경로만 알려주고 정상 흐름을 이어간다.
				if err := reporter.OpenInBrowser(outputPath); err != nil {
					fmt.Fprintf(os.Stderr, "리포트를 자동으로 열지 못했습니다 (%v)\n", err)
				}
				fmt.Fprintf(os.Stderr, "리포트 저장 위치: %s\n", outputPath)
			}

			if useExit && len(result.Findings) > 0 {
				findingsExit = true
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&rulesPath, "rules", "r", "", "룰셋 파일 경로 (기본: 내장 룰셋)")
	cmd.Flags().StringVarP(&format, "format", "f", formatText,
		"출력 형식 (text | json | md | html). html 은 리포트를 심은 대시보드 한 장을 만든다")
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
	cmd.Flags().StringVar(&baselinePath, "baseline", "",
		"이 baseline 파일에 있는 시크릿은 결과에서 제외 (신규 항목만 보고)")
	cmd.Flags().StringVar(&baselineOutPath, "baseline-out", "",
		"현재 탐지 결과를 baseline 파일로 저장 (--baseline 과 동시 사용 불가)")
	cmd.Flags().IntVar(&workers, "workers", 0,
		"정규식 매칭에 쓸 goroutine 수 (0 = CPU 코어 수만큼 자동)")
	cmd.Flags().BoolVar(&openReport, "open", false,
		"저장한 리포트를 기본 브라우저로 연다 (--output 을 생략하면 현재 폴더에 만든다)")
	return cmd
}

// emitReport는 리포트를 지정한 형식으로 표준 출력 또는 파일에 쓴다.
//
// 파일에 쓸 때 defer 대신 명시적으로 닫는 이유는, 바로 뒤에서 --open 이 같은
// 파일을 브라우저로 다시 열기 때문이다. 버퍼가 덜 비워진 채로 열리면 안 된다.
func emitReport(report reporter.Report, format, path string, color bool) error {
	if path == "" {
		return writeReport(os.Stdout, report, format, color && reporter.IsTerminal(os.Stdout))
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("결과 파일 생성 실패: %w", err)
	}
	// 파일로 나가는 출력에는 색상 코드를 넣지 않는다.
	if err := writeReport(f, report, format, false); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("결과 파일 저장 실패: %w", err)
	}
	return nil
}

func writeReport(w io.Writer, report reporter.Report, format string, color bool) error {
	switch format {
	case formatJSON:
		return reporter.WriteJSON(w, report)
	case formatMD:
		return reporter.WriteMarkdown(w, report)
	case formatHTML:
		return reporter.WriteHTML(w, report, secrethound.Dashboard)
	default:
		return reporter.WriteText(w, report, color)
	}
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
