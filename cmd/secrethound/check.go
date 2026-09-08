package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/whiteclover0542/secrethound/internal/collector"
	"github.com/whiteclover0542/secrethound/internal/reporter"
	"github.com/whiteclover0542/secrethound/internal/scanner"
)

// checkFormats는 check 가 한 번에 만들어 내는 리포트 형식이다.
// 둘의 쓸모가 다르다 — html 은 그 자리에서 보기 위한 것이고, md 는 남겨두거나
// 남에게 보내기 위한 것이다. 어느 쪽이 필요한지 사용자에게 묻지 않고 둘 다 만든다.
var checkFormats = []string{formatHTML, formatMD}

// checkCmd는 터미널에 익숙하지 않은 사용자를 위한 진입점이다.
//
// scan은 플래그를 조립할 줄 아는 사람과 CI를 위한 커맨드다. check는 그 반대로,
// 플래그를 하나도 주지 않아도 항상 옳은 기본값으로 끝까지 굴러가야 한다.
// 그래서 scan에서 사람이 직접 이어붙여야 했던 단계 — 히스토리 포함 여부 판단,
// 리포트 형식 선택, 파일 저장, 브라우저로 열기 — 를 하나로 묶는다.
func checkCmd() *cobra.Command {
	var (
		outDir   string
		noOpen   bool
		validate bool
		pick     bool
	)

	cmd := &cobra.Command{
		Use:   "check [폴더]",
		Short: "폴더 하나를 검사하고 결과를 브라우저로 열어준다 (가장 간단한 사용법)",
		Long: `폴더를 지정하면 검사부터 결과 보기까지 한 번에 끝낸다.

  1. 지정한 폴더가 git 저장소면 커밋 히스토리까지 함께 검사한다
  2. 결과를 HTML과 마크다운 두 가지로 저장한다
  3. HTML 리포트를 기본 브라우저로 연다

폴더를 생략하면 지금 있는 폴더를 검사한다.

시크릿을 찾아도 종료 코드는 0이다. 사람이 결과를 눈으로 보는 용도이기 때문이다.
CI에서 탐지 여부로 빌드를 실패시키려면 종료 코드를 나눠 주는 scan 을 쓰면 된다.`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			switch {
			case len(args) > 0:
				target = args[0]
			case pick:
				// 폴더를 직접 넘겼다면 그쪽이 우선이다. 창은 넘기지 않았을 때만 띄운다.
				picked, err := pickFolder("secrethound: 검사할 폴더를 선택하세요")
				if err != nil {
					return err
				}
				if picked == "" {
					fmt.Println("폴더를 선택하지 않아 종료합니다.")
					return nil
				}
				target = picked
			}

			if err := ensureDir(target); err != nil {
				return err
			}
			if outDir != "" {
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return fmt.Errorf("리포트를 저장할 폴더를 만들지 못했습니다: %w", err)
				}
			}

			// 사용자에게 --history 를 붙일지 묻는 대신, 가능하면 항상 켠다.
			// 과거 커밋에만 남은 키를 찾는 것이 이 도구를 쓰는 가장 큰 이유다.
			history, historySkipped := historyPlan(target)

			started := time.Now()
			rs, err := loadRuleset("")
			if err != nil {
				return err
			}

			result, err := scanner.Run(cmd.Context(), rs, scanner.Options{
				Target:  target,
				History: history,
				Validate: scanner.ValidateOptions{
					Enabled: validate,
					Timeout: 5 * time.Second,
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
				BaselineKnown:  result.BaselineKnown,
				Validated:      result.Validated,
				Validation:     result.Validation,
				Duration:       time.Since(started),
			})

			paths := make(map[string]string, len(checkFormats))
			for _, format := range checkFormats {
				path := filepath.Join(outDir, defaultReportName+formatExt[format])
				if err := emitReport(report, format, path, false); err != nil {
					return err
				}
				paths[format] = path
			}

			printCheckSummary(report, history, historySkipped)

			if !noOpen {
				if err := reporter.OpenInBrowser(paths[formatHTML]); err != nil {
					fmt.Printf("\n리포트를 자동으로 열지 못했습니다 (%v)\n", err)
					fmt.Println("아래 파일을 직접 열어보세요.")
				}
			}

			fmt.Println("\n저장된 리포트")
			for _, format := range checkFormats {
				if abs, err := filepath.Abs(paths[format]); err == nil {
					fmt.Printf("  %s\n", abs)
				} else {
					fmt.Printf("  %s\n", paths[format])
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outDir, "out", "", "리포트를 저장할 폴더 (기본: 지금 있는 폴더)")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "검사만 하고 브라우저를 열지 않는다")
	// exe 를 탐색기에서 더블클릭했을 때 쓰는 플래그다. 폴더 경로를 타이핑하는
	// 대신 창에서 고르게 한다 (cmd/secrethound/console_windows.go 참조).
	cmd.Flags().BoolVar(&pick, "pick", false,
		"검사할 폴더를 선택하는 창을 띄운다 (폴더를 직접 지정하면 무시됨, Windows 전용)")
	// scan과 같은 이유로 기본 비활성이다. 탐지한 자격증명을 발급처로 내보내는
	// 동작이라, 사용자가 모르는 사이에 일어나서는 안 된다.
	cmd.Flags().BoolVar(&validate, "validate", false,
		"탐지한 키가 지금도 살아있는지 발급처에 확인 (네트워크 사용, 기본 비활성)")
	return cmd
}

// historyPlan은 이 폴더에 히스토리 스캔을 켤지 정하고, 끄는 경우 그 이유를 함께
// 돌려준다. 이유를 남기는 것은 사용자가 "왜 과거 커밋은 안 봤는지" 알아야 저장소
// 폴더를 다시 지정할지 판단할 수 있기 때문이다.
func historyPlan(target string) (enabled bool, skipped string) {
	root := collector.RepoRoot(target)
	if root == "" {
		return false, "git 저장소가 아니라 커밋 히스토리는 검사하지 않았습니다"
	}
	// 저장소 최상위가 아닌 하위 폴더에서 히스토리를 켜면 고른 폴더와 무관한
	// 저장소 전체의 커밋을 훑게 되어, 사용자가 지정한 범위와 결과가 어긋난다.
	if !collector.IsRepoRoot(target) {
		return false, fmt.Sprintf("저장소의 최상위 폴더가 아니라 커밋 히스토리는 검사하지 않았습니다.\n"+
			"            히스토리까지 보려면 저장소 폴더를 지정하세요: %s", root)
	}
	if !collector.HasCommits(root) {
		return false, "아직 커밋이 없어 검사할 히스토리가 없습니다"
	}
	return true, ""
}

// printCheckSummary는 콘솔에 최소한만 남긴다. 자세한 내용은 리포트에 있고,
// 여기서는 "그래서 괜찮은가"와 "다음에 뭘 해야 하는가"만 답한다.
func printCheckSummary(r reporter.Report, history bool, historySkipped string) {
	fmt.Printf("검사한 곳   %s\n", r.Target)

	if history {
		fmt.Printf("검사 범위   지금 있는 파일 %d개 + 커밋 %d개\n",
			r.Summary.FilesScanned, r.Summary.CommitsScanned)
	} else {
		fmt.Printf("검사 범위   지금 있는 파일 %d개\n", r.Summary.FilesScanned)
		fmt.Printf("            %s\n", historySkipped)
	}

	if r.Summary.Findings == 0 {
		fmt.Println("결과        유출된 시크릿을 찾지 못했습니다.")
		return
	}

	line := fmt.Sprintf("%d건", r.Summary.Findings)
	if b := reporter.SeverityBreakdown(r.Summary.BySeverity); b != "" {
		line += " (" + b + ")"
	}
	fmt.Printf("결과        유출된 것으로 보이는 키 %s\n", line)
	fmt.Println()
	fmt.Println("! 파일에서 지우기 전에 발급처에서 키를 먼저 폐기(revoke)하세요.")
	fmt.Println("  지우기만 하면 키는 그대로 살아있습니다. 폐기 절차는 리포트에 있습니다.")

	if v := r.Summary.Validation; v != nil && v.Valid > 0 {
		fmt.Printf("! 그중 %d건은 지금도 살아있는 키로 확인되었습니다. 이것부터 폐기하세요.\n", v.Valid)
	}
}

func ensureDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("그런 폴더가 없습니다: %s", path)
		}
		return fmt.Errorf("폴더를 확인할 수 없습니다: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("폴더를 지정해야 합니다 (파일이 지정됨): %s", path)
	}
	return nil
}
