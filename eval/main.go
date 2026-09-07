// 평가 하네스: 레이블된 코퍼스로 스캐너의 precision / recall / F1 을 측정한다.
//
// 채점 단위는 (파일, 줄) 이다. 한 줄에서 여러 룰이 걸려도 1건으로 센다.
// 도구가 같은 줄을 중복 보고한다고 해서 불리해지지 않도록 하기 위함이다.
//
// 코퍼스 디렉토리 이름이 _corpus 인 이유: Go 툴체인은 `_` 로 시작하는 디렉토리를 무시한다.
// 코퍼스에는 컴파일되지 않는 가짜 Go 파일이 들어 있어, 이렇게 하지 않으면
// go build / go vet / go test 가 전부 깨진다.
//
//	go run ./eval                 # secrethound 측정
//	go run ./eval --tool gitleaks # gitleaks 측정 (설치되어 있어야 함)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/scanner"
	"gopkg.in/yaml.v3"
)

type labelFile struct {
	Version int     `yaml:"version"`
	Cases   []cases `yaml:"cases"`
}

type cases struct {
	Path    string  `yaml:"path"`
	Secrets []entry `yaml:"secrets"`
	Traps   []entry `yaml:"traps"`
}

type entry struct {
	Line int    `yaml:"line"`
	Kind string `yaml:"kind"`
	Note string `yaml:"note"`
}

// location은 채점 단위인 (파일, 줄) 쌍이다.
type location struct {
	Path string
	Line int
}

// prediction은 도구가 한 위치에서 보고한 내용이다.
type prediction struct {
	RuleID   string
	Severity string
}

// misclassified는 시크릿을 찾긴 했으나 다른 종류로 분류한 경우다.
// precision/recall 로는 드러나지 않지만 사용자에게는 심각도가 틀리게 보고된다.
type misclassified struct {
	Loc      location
	Expected string
	Actual   string
	Severity string
}

type metrics struct {
	Tool      string
	TP        int
	FP        int
	FN        int
	FalseHits []location
	Missed    []location
	Misclass  []misclassified
}

func (m metrics) precision() float64 {
	if m.TP+m.FP == 0 {
		return 0
	}
	return float64(m.TP) / float64(m.TP+m.FP)
}

func (m metrics) recall() float64 {
	if m.TP+m.FN == 0 {
		return 0
	}
	return float64(m.TP) / float64(m.TP+m.FN)
}

func (m metrics) f1() float64 {
	p, r := m.precision(), m.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func main() {
	var (
		corpusPath = flag.String("corpus", "eval/_corpus", "평가 코퍼스 경로")
		labelsPath = flag.String("labels", "eval/labels.yaml", "정답 레이블 파일")
		tool       = flag.String("tool", "secrethound", "측정 대상 (secrethound | gitleaks)")
		rulesPath  = flag.String("rules", "", "secrethound 룰셋 경로 (기본: 내장 룰셋)")
		markdown   = flag.Bool("markdown", false, "결과를 마크다운 표로 출력")
		coverage   = flag.Bool("coverage", false, "코퍼스가 어떤 룰을 검증하는지 출력")
		history    = flag.Bool("history", false, "git 히스토리 스캔 시나리오 평가")
		historyDef = flag.String("history-spec", "eval/history.yaml", "히스토리 시나리오 정의 파일")
	)
	flag.Parse()

	if *history {
		if err := runHistoryEval(*historyDef, *rulesPath); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	if *coverage {
		if err := printCoverage(*corpusPath, *rulesPath); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		return
	}

	labels, traps, err := loadLabels(*labelsPath, *corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	var predictions map[location]prediction
	switch *tool {
	case "secrethound":
		predictions, err = runSecrethound(*corpusPath, *rulesPath)
	case "gitleaks":
		predictions, err = runGitleaks(*corpusPath)
	default:
		err = fmt.Errorf("알 수 없는 도구: %s", *tool)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// 룰 ID 체계는 도구마다 달라 secrethound에 대해서만 분류 정확도를 확인한다.
	m := score(*tool, labels, predictions, *tool == "secrethound")
	if *markdown {
		printMarkdown(m, len(labels), len(traps))
		return
	}
	printReport(m, labels, traps)

	// CI에서 회귀를 잡으려면 결과가 종료 코드로 드러나야 한다.
	// 기준선이 완벽한 상태이므로 오탐/미탐/오분류가 하나라도 생기면 실패로 본다.
	// 고칠 수 없는 사례는 labels.yaml 에 한계로 명시해 기대값 자체를 바꾼다.
	if *tool == "secrethound" && (m.FP > 0 || m.FN > 0 || len(m.Misclass) > 0) {
		os.Exit(1)
	}
}

// loadLabels는 레이블을 읽고 코퍼스의 모든 파일이 레이블에 등재되어 있는지 검증한다.
// 누락된 파일이 있으면 그 파일의 탐지 결과가 조용히 오탐으로 잡혀 수치가 왜곡된다.
func loadLabels(labelsPath, corpusPath string) (map[location]entry, map[location]entry, error) {
	data, err := os.ReadFile(labelsPath)
	if err != nil {
		return nil, nil, err
	}

	var lf labelFile
	if err := yaml.Unmarshal(data, &lf); err != nil {
		return nil, nil, fmt.Errorf("레이블 파싱 실패: %w", err)
	}

	secrets := make(map[location]entry)
	traps := make(map[location]entry)
	labeled := make(map[string]bool)

	for _, c := range lf.Cases {
		labeled[c.Path] = true
		for _, e := range c.Secrets {
			secrets[location{c.Path, e.Line}] = e
		}
		for _, e := range c.Traps {
			traps[location{c.Path, e.Line}] = e
		}
	}

	var missing []string
	err = filepath.WalkDir(corpusPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(corpusPath, path)
		rel = filepath.ToSlash(rel)
		if !labeled[rel] {
			missing = append(missing, rel)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("레이블에 없는 코퍼스 파일: %s", strings.Join(missing, ", "))
	}

	return secrets, traps, nil
}

func runSecrethound(corpusPath, rulesPath string) (map[location]prediction, error) {
	rs, err := loadRuleset(rulesPath)
	if err != nil {
		return nil, err
	}

	result, err := scanner.Run(context.Background(), rs, scanner.Options{Target: corpusPath})
	if err != nil {
		return nil, err
	}

	predictions := make(map[location]prediction)
	for _, f := range result.Findings {
		predictions[location{filepath.ToSlash(f.Path), f.Line}] = prediction{
			RuleID:   f.RuleID,
			Severity: string(f.Severity),
		}
	}
	return predictions, nil
}

// printCoverage는 코퍼스가 실제로 검증하는 룰과 그렇지 않은 룰을 보여준다.
// 한 번도 발동하지 않은 룰은 정규식이 틀려도 알 수 없는 상태이므로 코퍼스 보강 대상이다.
//
// 판정 기준은 "최종 결과에 나타났는가"다. 매칭은 됐지만 오탐 필터나 중복 제거로
// 사라진 룰은 실제 사용자에게 도달하지 않으므로 검증된 것으로 보지 않는다.
func printCoverage(corpusPath, rulesPath string) error {
	rs, err := loadRuleset(rulesPath)
	if err != nil {
		return err
	}

	result, err := scanner.Run(context.Background(), rs, scanner.Options{Target: corpusPath})
	if err != nil {
		return err
	}

	hits := make(map[string]int)
	for _, f := range result.Findings {
		hits[f.RuleID]++
	}

	var covered, uncovered []string
	for _, r := range rs.Rules {
		if hits[r.ID] > 0 {
			covered = append(covered, fmt.Sprintf("  %-30s %d건", r.ID, hits[r.ID]))
			continue
		}
		uncovered = append(uncovered, fmt.Sprintf("  %-30s %s", r.ID, r.Description))
	}

	fmt.Printf("룰 커버리지: %d / %d\n\n", len(covered), len(rs.Rules))
	fmt.Printf("검증됨 (%d)\n%s\n", len(covered), strings.Join(covered, "\n"))
	if len(uncovered) > 0 {
		fmt.Printf("\n미검증 (%d) — 코퍼스에 해당 케이스가 없어 한 번도 실행되지 않음\n%s\n",
			len(uncovered), strings.Join(uncovered, "\n"))
		// 룰만 추가하고 코퍼스 케이스를 빠뜨리는 것을 CI에서 막는다.
		return fmt.Errorf("검증되지 않은 룰이 %d개 있습니다", len(uncovered))
	}
	return nil
}

func loadRuleset(path string) (*config.Ruleset, error) {
	if path != "" {
		return config.Load(path)
	}
	return config.Parse(secrethound.DefaultRuleset)
}

type gitleaksFinding struct {
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	RuleID    string `json:"RuleID"`
}

func runGitleaks(corpusPath string) (map[location]prediction, error) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		return nil, fmt.Errorf("gitleaks가 설치되어 있지 않습니다 (go install github.com/gitleaks/gitleaks/v8@latest)")
	}

	report, err := os.CreateTemp("", "gitleaks-*.json")
	if err != nil {
		return nil, err
	}
	report.Close()
	defer os.Remove(report.Name())

	// gitleaks는 탐지 시 종료 코드 1을 반환하므로 exit status 자체는 실패로 보지 않는다.
	cmd := exec.Command("gitleaks", "detect",
		"--source", corpusPath,
		"--no-git",
		"--report-format", "json",
		"--report-path", report.Name(),
		"--exit-code", "0",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gitleaks 실행 실패: %w\n%s", err, out)
	}

	data, err := os.ReadFile(report.Name())
	if err != nil {
		return nil, err
	}

	var findings []gitleaksFinding
	if len(data) > 0 {
		if err := json.Unmarshal(data, &findings); err != nil {
			return nil, fmt.Errorf("gitleaks 리포트 파싱 실패: %w", err)
		}
	}

	predictions := make(map[location]prediction)
	for _, f := range findings {
		path := filepath.ToSlash(f.File)
		if rel, err := filepath.Rel(corpusPath, f.File); err == nil {
			path = filepath.ToSlash(rel)
		}
		predictions[location{path, f.StartLine}] = prediction{RuleID: f.RuleID}
	}
	return predictions, nil
}

func score(tool string, labels map[location]entry, predictions map[location]prediction, checkKind bool) metrics {
	m := metrics{Tool: tool}

	for loc, p := range predictions {
		label, ok := labels[loc]
		if !ok {
			m.FP++
			m.FalseHits = append(m.FalseHits, loc)
			continue
		}

		m.TP++
		if checkKind && label.Kind != "" && label.Kind != p.RuleID {
			m.Misclass = append(m.Misclass, misclassified{
				Loc:      loc,
				Expected: label.Kind,
				Actual:   p.RuleID,
				Severity: p.Severity,
			})
		}
	}

	for loc := range labels {
		if _, ok := predictions[loc]; !ok {
			m.FN++
			m.Missed = append(m.Missed, loc)
		}
	}

	sortLocations(m.FalseHits)
	sortLocations(m.Missed)
	sort.Slice(m.Misclass, func(i, j int) bool {
		return m.Misclass[i].Loc.Path < m.Misclass[j].Loc.Path
	})
	return m
}

func sortLocations(locs []location) {
	sort.Slice(locs, func(i, j int) bool {
		if locs[i].Path != locs[j].Path {
			return locs[i].Path < locs[j].Path
		}
		return locs[i].Line < locs[j].Line
	})
}

func printReport(m metrics, labels, traps map[location]entry) {
	fmt.Printf("도구: %s\n", m.Tool)
	fmt.Printf("코퍼스: 실제 시크릿 %d건, 오탐 유발 케이스 %d건\n\n", len(labels), len(traps))

	fmt.Printf("  TP %3d   탐지 성공\n", m.TP)
	fmt.Printf("  FP %3d   오탐\n", m.FP)
	fmt.Printf("  FN %3d   미탐\n\n", m.FN)

	fmt.Printf("  Precision  %.3f   (탐지한 것 중 진짜 비율)\n", m.precision())
	fmt.Printf("  Recall     %.3f   (진짜 중 탐지한 비율)\n", m.recall())
	fmt.Printf("  F1         %.3f\n", m.f1())

	if len(m.Missed) > 0 {
		fmt.Printf("\n미탐 (%d건) — 놓친 실제 시크릿\n", len(m.Missed))
		for _, loc := range m.Missed {
			fmt.Printf("  %s:%d  %s\n", loc.Path, loc.Line, labels[loc].Note)
		}
	}

	if len(m.FalseHits) > 0 {
		fmt.Printf("\n오탐 (%d건) — 시크릿이 아닌데 탐지한 것\n", len(m.FalseHits))
		for _, loc := range m.FalseHits {
			note := "레이블에 없는 줄"
			if t, ok := traps[loc]; ok {
				note = t.Note
			}
			fmt.Printf("  %s:%d  %s\n", loc.Path, loc.Line, note)
		}
	}

	if len(m.Misclass) > 0 {
		fmt.Printf("\n오분류 (%d건) — 탐지는 했으나 다른 종류로 보고 (심각도가 틀리게 나간다)\n", len(m.Misclass))
		for _, mc := range m.Misclass {
			fmt.Printf("  %s:%d  기대 %s → 실제 %s (%s)\n",
				mc.Loc.Path, mc.Loc.Line, mc.Expected, mc.Actual, mc.Severity)
		}
	}
}

func printMarkdown(m metrics, secrets, traps int) {
	fmt.Println("| 도구 | Precision | Recall | F1 | TP | FP | FN |")
	fmt.Println("|---|---:|---:|---:|---:|---:|---:|")
	fmt.Printf("| %s | %.3f | %.3f | %.3f | %d | %d | %d |\n",
		m.Tool, m.precision(), m.recall(), m.f1(), m.TP, m.FP, m.FN)
	fmt.Printf("\n코퍼스: 실제 시크릿 %d건, 오탐 유발 케이스 %d건\n", secrets, traps)
}
