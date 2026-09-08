package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/whiteclover0542/secrethound/internal/collector"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/reporter"
	"github.com/whiteclover0542/secrethound/internal/scanner"
)

// checkFormats는 check 가 한 번에 만들어 내는 리포트 형식이다.
// 둘의 쓸모가 다르다 — html 은 그 자리에서 보기 위한 것이고, md 는 남겨두거나
// 남에게 보내기 위한 것이다. 어느 쪽이 필요한지 사용자에게 묻지 않고 둘 다 만든다.
var checkFormats = []string{formatHTML, formatMD}

// defaultReportDir는 리포트를 모아 두는 폴더 이름이다.
//
// 프로그램이 있는 폴더에 리포트를 바로 쏟으면, 저장소를 몇 개만 검사해도 파일이
// 금세 뒤섞여 실행 파일을 찾기 어려워진다. 한 겹 안으로 넣어 분리한다.
// --out 을 주면 그 경로를 그대로 쓴다 (이 이름을 덧붙이지 않는다).
const defaultReportDir = "secrethound-결과"

// maxSearchDepth는 저장소를 찾아 내려갈 최대 깊이다.
//
// 한 단계로는 부족하다 — 저장소를 같은 이름의 폴더로 한 번 감싸두는 배치가 흔하다
// (projects/myapp/myapp). 반대로 제한이 없으면 홈 디렉토리를 고른 순간 디스크
// 전체를 훑게 된다. 3단계면 projects/조직/저장소 같은 배치까지 닿는다.
const maxSearchDepth = 3

// maxReportSuffix는 같은 이름의 리포트를 몇 번까지 번호를 붙여 늘릴지다.
// 여기에 걸릴 정도면 사용자가 리포트를 정리하지 않은 것이므로, 조용히 덮어쓰는
// 대신 오류로 알린다.
const maxReportSuffix = 999

// scanOutcome은 대상 하나를 검사한 결과다. 여러 폴더를 한 번에 검사할 수 있으므로
// 요약 출력과 리포트 열기를 위해 결과를 모아 둔다.
type scanOutcome struct {
	target      string
	report      reporter.Report
	history     bool
	historyNote string
	paths       map[string]string // 형식 → 저장한 파일 경로
}

// checkCmd는 터미널에 익숙하지 않은 사용자를 위한 진입점이다.
//
// scan은 플래그를 조립할 줄 아는 사람과 CI를 위한 커맨드다. check는 그 반대로,
// 플래그를 하나도 주지 않아도 항상 옳은 기본값으로 끝까지 굴러가야 한다.
// 그래서 scan에서 사람이 직접 이어붙여야 했던 단계 — 검사 대상 결정, 히스토리 포함
// 여부 판단, 리포트 형식 선택, 파일 저장, 브라우저로 열기 — 를 하나로 묶는다.
func checkCmd() *cobra.Command {
	var (
		outDir   string
		noOpen   bool
		validate bool
		pick     bool
	)

	cmd := &cobra.Command{
		Use:   "check [폴더...]",
		Short: "폴더를 검사하고 결과를 브라우저로 열어준다 (가장 간단한 사용법)",
		Long: `폴더를 지정하면 검사부터 결과 보기까지 한 번에 끝낸다.

  1. 지정한 폴더가 git 저장소면 커밋 히스토리까지 함께 검사한다
  2. 결과를 HTML과 마크다운 두 가지로 저장한다
  3. HTML 리포트를 기본 브라우저로 연다

폴더를 여러 개 지정하면 각각 검사해 저장소별로 리포트를 만든다. 저장소가 아닌
폴더를 지정했는데 그 바로 아래에 저장소들이 있으면, 그것들을 찾아 전부 검사한다.
프로젝트를 한곳에 모아두는 폴더(예: C:\projects)를 지정하면 되게 하기 위해서다.

폴더를 생략하면 지금 있는 폴더를 검사한다.

시크릿을 찾아도 종료 코드는 0이다. 사람이 결과를 눈으로 보는 용도이기 때문이다.
CI에서 탐지 여부로 빌드를 실패시키려면 종료 코드를 나눠 주는 scan 을 쓰면 된다.`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			roots, err := selectRoots(args, pick)
			if err != nil {
				return err
			}
			if len(roots) == 0 {
				return nil // 사용자가 폴더 선택을 취소했다
			}

			targets, err := expandTargets(roots)
			if err != nil {
				return err
			}

			// --out 을 주지 않았으면 지금 있는 폴더 아래에 결과 폴더를 만든다.
			if outDir == "" {
				outDir = defaultReportDir
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("리포트를 저장할 폴더를 만들지 못했습니다: %w", err)
			}

			rs, err := loadRuleset("")
			if err != nil {
				return err
			}

			if len(targets) > 1 {
				fmt.Printf("검사할 폴더 %d개를 찾았습니다.\n\n", len(targets))
			}

			outcomes := make([]scanOutcome, 0, len(targets))
			for i, target := range targets {
				if len(targets) > 1 {
					fmt.Printf("[%d/%d] %s\n", i+1, len(targets), target)
				}

				outcome, err := scanOne(cmd.Context(), rs, target, outDir, validate)
				if err != nil {
					return err
				}
				printCheckSummary(outcome)
				fmt.Println()

				outcomes = append(outcomes, outcome)
			}

			printTotals(outcomes)
			printReportPaths(outcomes)

			if !noOpen {
				openResults(outcomes, outDir)
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

// selectRoots는 사용자가 무엇을 검사하라고 했는지 정한다.
// 빈 슬라이스를 돌려주면 폴더 선택을 취소한 것이다.
func selectRoots(args []string, pick bool) ([]string, error) {
	if len(args) > 0 {
		for _, a := range args {
			if err := ensureDir(a); err != nil {
				return nil, err
			}
		}
		return args, nil
	}

	if !pick {
		if err := ensureDir("."); err != nil {
			return nil, err
		}
		return []string{"."}, nil
	}

	// 창이 뜨기까지 잠깐 걸린다. 아무 안내도 없으면 빈 검은 창만 보여서
	// 프로그램이 안 켜진 것으로 오해하기 쉽다.
	fmt.Println("검사할 폴더를 선택하는 창을 띄우는 중입니다...")
	fmt.Println("창이 보이지 않으면 다른 창 뒤에 있는지, 작업 표시줄을 확인하세요.")
	fmt.Println()

	picked, err := pickFolder("secrethound: 검사할 폴더를 선택하세요")
	if err != nil {
		return nil, err
	}
	if picked == "" {
		fmt.Println("폴더를 선택하지 않아 종료합니다.")
		return nil, nil
	}
	if err := ensureDir(picked); err != nil {
		return nil, err
	}
	return []string{picked}, nil
}

// expandTargets는 지정된 폴더들을 실제로 검사할 폴더 목록으로 편다.
//
// 저장소가 아닌 폴더를 지정했으면 그 아래에서 저장소를 찾아 대신 검사한다.
// 사용자가 프로젝트를 모아두는 폴더를 고르는 것이 자연스럽기 때문이다.
func expandTargets(roots []string) ([]string, error) {
	return expandTargetsDepth(roots, maxSearchDepth)
}

func expandTargetsDepth(roots []string, depth int) ([]string, error) {
	var targets []string
	seen := make(map[string]bool)

	add := func(path string) {
		key := path
		if abs, err := filepath.Abs(path); err == nil {
			key = strings.ToLower(abs)
		}
		if !seen[key] {
			seen[key] = true
			targets = append(targets, path)
		}
	}

	for _, root := range roots {
		if isRepoDir(root) {
			add(root)
			continue
		}

		found, err := findRepos(root, depth)
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			// 저장소도 아니고 아래에 저장소도 없다. 그래도 파일 검사는 의미가 있다.
			add(root)
			continue
		}
		for _, c := range found {
			add(c)
		}
	}
	return targets, nil
}

// findRepos는 폴더 아래에서 git 저장소를 찾아 이름순으로 돌려준다.
//
// 저장소를 찾으면 그 안으로는 더 내려가지 않는다. 서브모듈까지 따로 잡으면 같은
// 파일을 두 번 검사하게 된다.
func findRepos(root string, depth int) ([]string, error) {
	if depth <= 0 {
		return nil, nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("폴더를 읽지 못했습니다: %w", err)
	}

	var repos []string
	for _, e := range entries {
		if !e.IsDir() || skipSearchDir(e.Name()) {
			continue
		}

		path := filepath.Join(root, e.Name())
		if isRepoDir(path) {
			repos = append(repos, path)
			continue
		}

		// 권한이 없거나 읽을 수 없는 폴더는 건너뛴다. 하나 때문에 전체 검사를
		// 멈출 이유가 없다.
		sub, err := findRepos(path, depth-1)
		if err != nil {
			continue
		}
		repos = append(repos, sub...)
	}

	sort.Strings(repos)
	return repos, nil
}

// isRepoDir는 폴더가 git 저장소의 최상위인지 .git 의 존재만으로 판단한다.
//
// collector.IsRepoRoot 는 git 을 실행해 정확히 답하지만 호출마다 프로세스를 하나씩
// 띄운다. 저장소를 찾느라 폴더 수백 개를 훑는 이 경로에서는 그 비용이 그대로 대기
// 시간이 된다. 서브모듈·워크트리는 .git 이 파일이므로 종류는 따지지 않는다.
// 히스토리를 실제로 읽을 수 있는지는 historyPlan 이 git 에게 다시 확인한다.
func isRepoDir(path string) bool {
	_, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil
}

// skipSearchDir는 저장소를 찾을 때 들어가 볼 필요가 없는 폴더를 걸러낸다.
// 크고 깊은데 그 안에 사용자의 저장소가 있을 리 없는 것들이다.
func skipSearchDir(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch strings.ToLower(name) {
	case "node_modules", "vendor", "venv", "__pycache__",
		"dist", "build", "target", "bin", "obj":
		return true
	}
	return false
}

func scanOne(ctx context.Context, rs *config.Ruleset, target, outDir string, validate bool) (scanOutcome, error) {
	// 사용자에게 --history 를 붙일지 묻는 대신, 가능하면 항상 켠다.
	// 과거 커밋에만 남은 키를 찾는 것이 이 도구를 쓰는 가장 큰 이유다.
	history, historyNote := historyPlan(target)

	started := time.Now()
	result, err := scanner.Run(ctx, rs, scanner.Options{
		Target:  target,
		History: history,
		Validate: scanner.ValidateOptions{
			Enabled: validate,
			Timeout: 5 * time.Second,
		},
	})
	if err != nil {
		return scanOutcome{}, err
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

	paths, err := reportPaths(outDir, target)
	if err != nil {
		return scanOutcome{}, err
	}
	for format, path := range paths {
		if err := emitReport(report, format, path, false); err != nil {
			return scanOutcome{}, err
		}
	}

	return scanOutcome{
		target:      target,
		report:      report,
		history:     history,
		historyNote: historyNote,
		paths:       paths,
	}, nil
}

// reportPaths는 검사 대상 폴더 이름을 붙여 겹치지 않는 리포트 파일 경로를 고른다.
//
// 이름에 폴더를 넣는 이유는 두 가지다. 여러 저장소를 한 번에 검사할 때 어느 결과가
// 어느 저장소 것인지 알아야 하고, 다른 저장소를 검사했다고 이전 결과가 사라지면
// 안 되기 때문이다. 같은 폴더를 다시 검사하면 -1, -2 를 붙여 이전 것을 남긴다.
//
// 한 검사에서 나온 html 과 md 는 반드시 같은 번호를 쓴다. 둘 중 하나만 이미 있어도
// 번호를 함께 올리는 이유가 이것이다 — 짝이 어긋나면 어느 md 가 어느 html 인지
// 알 수 없게 된다.
func reportPaths(outDir, target string) (map[string]string, error) {
	base := defaultReportName
	if name := targetName(target); name != "" {
		base += "-" + name
	}

	for i := 0; i <= maxReportSuffix; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i)
		}

		paths := make(map[string]string, len(checkFormats))
		free := true
		for _, format := range checkFormats {
			path := filepath.Join(outDir, candidate+formatExt[format])
			if _, err := os.Stat(path); err == nil {
				free = false
				break
			}
			paths[format] = path
		}
		if free {
			return paths, nil
		}
	}
	return nil, fmt.Errorf("%s 로 시작하는 리포트가 이미 %d개 있습니다. 오래된 것을 지우고 다시 실행하세요",
		base, maxReportSuffix)
}

// targetName은 파일 이름에 넣을 수 있는 형태로 대상 폴더 이름을 다듬는다.
// 경로 구분자나 드라이브 문자처럼 파일 이름에 못 쓰는 문자가 섞여 들어오면
// 파일 생성 자체가 실패하므로 걸러낸다.
func targetName(target string) string {
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	name := filepath.Base(abs)

	// 드라이브 루트(C:\)처럼 이름이라 할 만한 게 없는 경우가 있다.
	if name == "." || name == string(filepath.Separator) {
		name = strings.TrimSuffix(filepath.VolumeName(abs), ":")
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20, strings.ContainsRune(`<>:"/\|?*`, r):
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	return strings.Trim(strings.TrimSpace(b.String()), ".")
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
func printCheckSummary(o scanOutcome) {
	r := o.report

	fmt.Printf("검사한 곳   %s\n", r.Target)

	if o.history {
		fmt.Printf("검사 범위   지금 있는 파일 %d개 + 커밋 %d개\n",
			r.Summary.FilesScanned, r.Summary.CommitsScanned)
	} else {
		fmt.Printf("검사 범위   지금 있는 파일 %d개\n", r.Summary.FilesScanned)
		fmt.Printf("            %s\n", o.historyNote)
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

	if v := r.Summary.Validation; v != nil && v.Valid > 0 {
		fmt.Printf("            그중 %d건은 지금도 살아있는 키로 확인되었습니다\n", v.Valid)
	}
}

// printTotals는 여러 폴더를 검사했을 때만 전체 합계를 덧붙인다.
// 하나뿐이면 바로 위에 같은 숫자가 이미 있으므로 반복하지 않는다.
func printTotals(outcomes []scanOutcome) {
	if len(outcomes) < 2 {
		printNextStep(hasFindings(outcomes))
		return
	}

	total, withFindings := 0, 0
	for _, o := range outcomes {
		total += o.report.Summary.Findings
		if o.report.Summary.Findings > 0 {
			withFindings++
		}
	}

	fmt.Println(strings.Repeat("─", 60))
	if total == 0 {
		fmt.Printf("전체        폴더 %d개에서 유출된 시크릿을 찾지 못했습니다.\n", len(outcomes))
		return
	}

	fmt.Printf("전체        폴더 %d개 중 %d개에서 %d건\n", len(outcomes), withFindings, total)
	for _, o := range outcomes {
		if n := o.report.Summary.Findings; n > 0 {
			fmt.Printf("            %-30s %d건\n", targetName(o.target), n)
		}
	}
	printNextStep(true)
}

func printNextStep(found bool) {
	if !found {
		return
	}
	fmt.Println()
	fmt.Println("! 파일에서 지우기 전에 발급처에서 키를 먼저 폐기(revoke)하세요.")
	fmt.Println("  지우기만 하면 키는 그대로 살아있습니다. 폐기 절차는 리포트에 있습니다.")
}

func printReportPaths(outcomes []scanOutcome) {
	fmt.Println("\n저장된 리포트")
	for _, o := range outcomes {
		for _, format := range checkFormats {
			path := o.paths[format]
			if abs, err := filepath.Abs(path); err == nil {
				path = abs
			}
			fmt.Printf("  %s\n", path)
		}
	}
}

// openResults는 결과를 사용자 눈앞에 띄운다.
//
// 폴더가 하나면 리포트를 바로 연다. 여럿이면 탭이 그 수만큼 열려 오히려 방해가
// 되므로, 리포트가 모여 있는 폴더를 대신 연다.
func openResults(outcomes []scanOutcome, outDir string) {
	if len(outcomes) == 1 {
		if err := reporter.OpenInBrowser(outcomes[0].paths[formatHTML]); err != nil {
			fmt.Printf("\n리포트를 자동으로 열지 못했습니다 (%v)\n", err)
			fmt.Println("위 파일을 직접 열어보세요.")
		}
		return
	}

	dir := outDir
	if dir == "" {
		dir = "."
	}
	if err := reporter.OpenInBrowser(dir); err != nil {
		fmt.Printf("\n리포트 폴더를 자동으로 열지 못했습니다 (%v)\n", err)
	}
}

func hasFindings(outcomes []scanOutcome) bool {
	for _, o := range outcomes {
		if o.report.Summary.Findings > 0 {
			return true
		}
	}
	return false
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
