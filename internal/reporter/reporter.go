package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
	"github.com/whiteclover0542/secrethound/internal/validator"
)

type Summary struct {
	FilesScanned   int            `json:"files_scanned"`
	FilesSkipped   int            `json:"files_skipped"`
	CommitsScanned int            `json:"commits_scanned"`
	Findings       int            `json:"findings"`
	FilteredOut    int            `json:"filtered_out"`
	BaselineKnown  int            `json:"baseline_known,omitempty"`
	BySeverity     map[string]int `json:"by_severity"`
	DurationMS     int64          `json:"duration_ms"`

	// Validation은 --validate 를 켰을 때만 채워진다.
	// 켜지 않은 스캔과 구분되도록 nil을 유지한다.
	Validation *ValidationSummary `json:"validation,omitempty"`
}

// ValidationSummary는 발급처 확인 결과 집계다.
// Valid만이 "지금 위험한 키"의 개수이고, Revoked는 위험이 사라졌다는 뜻일 뿐
// 탐지가 틀렸다는 뜻이 아니다 (validator 패키지 주석 참조).
type ValidationSummary struct {
	Checked     int  `json:"checked"`
	Valid       int  `json:"valid"`
	Revoked     int  `json:"revoked"`
	Unknown     int  `json:"unknown"`
	Unsupported int  `json:"unsupported"`
	Offline     bool `json:"offline"`
}

// Report는 CLI 출력과 JSON 출력이 공유하는 표준 결과 포맷이다.
// 대시보드와 CI가 이 JSON을 그대로 소비한다.
type Report struct {
	Tool      string            `json:"tool"`
	Version   string            `json:"version"`
	Target    string            `json:"target"`
	ScannedAt time.Time         `json:"scanned_at"`
	Summary   Summary           `json:"summary"`
	Findings  []finding.Finding `json:"findings"`
}

type Input struct {
	Target         string
	Version        string
	Findings       []finding.Finding
	FilesScanned   int
	FilesSkipped   int
	CommitsScanned int
	FilteredOut    int
	BaselineKnown  int
	Validated      bool
	Validation     validator.Stats
	Duration       time.Duration
}

func Build(in Input) Report {
	// nil 슬라이스는 JSON에서 null 로 나간다. 탐지가 0건일 때 "findings": null 이
	// 되면 배열을 기대하는 쪽이 전부 깨진다 — 대시보드는 리포트를 못 읽고, .length
	// 를 쓰는 CI 스크립트는 오류를 낸다. 길이 0으로 만들어 항상 [] 로 나가게 한다.
	findings := make([]finding.Finding, 0, len(in.Findings))
	findings = append(findings, in.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		// 살아있다고 확인된 키가 맨 위로 온다. 심각도보다 앞세우는 이유는,
		// 검증을 켠 사용자가 알고 싶은 것이 "지금 당장 폐기해야 할 키"이기 때문이다.
		if ra, rb := validationRank(a), validationRank(b); ra != rb {
			return ra < rb
		}
		if ra, rb := config.SeverityRank(a.Severity), config.SeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})

	bySeverity := make(map[string]int)
	for i := range findings {
		bySeverity[string(findings[i].Severity)]++
		// 히스토리에서 발견된 경우에만 정리 명령을 붙인다. 워킹트리에만 있는
		// 파일은 그냥 지우면 되므로 필요 없다.
		if findings[i].Commit != "" {
			findings[i].HistoryCleanup = historyCleanupCommand(findings[i].Path)
		}
	}

	summary := Summary{
		FilesScanned:   in.FilesScanned,
		FilesSkipped:   in.FilesSkipped,
		CommitsScanned: in.CommitsScanned,
		Findings:       len(findings),
		FilteredOut:    in.FilteredOut,
		BaselineKnown:  in.BaselineKnown,
		BySeverity:     bySeverity,
		DurationMS:     in.Duration.Milliseconds(),
	}
	if in.Validated {
		summary.Validation = &ValidationSummary{
			Checked:     in.Validation.Checked,
			Valid:       in.Validation.Valid,
			Revoked:     in.Validation.Revoked,
			Unknown:     in.Validation.Unknown,
			Unsupported: in.Validation.Unsupported,
			Offline:     in.Validation.Offline,
		}
	}

	return Report{
		Tool:      "secrethound",
		Version:   in.Version,
		Target:    in.Target,
		ScannedAt: time.Now(),
		Findings:  findings,
		Summary:   summary,
	}
}

// validationRank는 정렬 우선순위다. 검증하지 않은 스캔에서는 전부 같은 값이라
// 기존 심각도 정렬이 그대로 유지된다.
func validationRank(f finding.Finding) int {
	if f.Validation == nil {
		return 1
	}
	switch f.Validation.Status {
	case validator.StatusValid:
		return 0
	case validator.StatusRevoked:
		return 2
	}
	return 1
}

func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteText(w io.Writer, r Report, color bool) error {
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "탐지된 시크릿이 없습니다.")
		writeSummary(w, r)
		return nil
	}

	locWidth, ruleWidth := 0, 0
	for _, f := range r.Findings {
		locWidth = max(locWidth, len(location(f)))
		ruleWidth = max(ruleWidth, len(f.RuleID))
	}

	for _, f := range r.Findings {
		fmt.Fprintf(w, "%s  %-*s  %-*s  %s  (%s)\n",
			severityLabel(f.Severity, color), locWidth, location(f),
			ruleWidth, f.RuleID, f.Masked, annotation(f))
	}

	writeSummary(w, r)
	writeRemediation(w, r.Findings)
	return nil
}

// historyCleanupCommand는 히스토리에서 이 파일을 완전히 제거하는 git filter-repo
// 명령을 만든다. 값 하나만 지우는 --replace-text 방식도 있지만, 원본 시크릿 값을
// 리포트에 담지 않는다는 설계(Masked 참조)와 상충해 쓸 수 없다 — 값이 있어야 정확한
// 치환 규칙을 만들 수 있는데, 그 값 자체가 유출 경로가 되면 안 되기 때문이다.
// 대신 파일 단위 제거를 기본으로 안내하고, 값만 지우고 싶다면 사용자가 직접
// --replace-text 규칙을 구성하도록 안내 문구를 덧붙인다.
func historyCleanupCommand(path string) string {
	return "git filter-repo --path " + shellQuote(path) + " --invert-paths"
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// remediationGuide는 리포트 하단 "대응 방법"에 실리는 폐기 절차 한 건이다.
type remediationGuide struct {
	ruleID string
	text   string
}

// collectRemediation은 폐기 절차와 히스토리 정리 명령을 중복 없이 모은다.
// 같은 룰이 여러 건 잡혀도 절차는 한 번, 같은 파일이 여러 건이어도 명령은 한 번만
// 싣는다. 텍스트 출력과 마크다운 출력이 같은 목록을 쓰도록 여기서 한 번만 계산한다.
func collectRemediation(findings []finding.Finding) ([]remediationGuide, []string) {
	var guides []remediationGuide
	var cleanups []string
	seenRule := make(map[string]bool)
	seenPath := make(map[string]bool)

	for _, f := range findings {
		if f.Remediation != "" && !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			guides = append(guides, remediationGuide{f.RuleID, f.Remediation})
		}
		if f.HistoryCleanup != "" && !seenPath[f.Path] {
			seenPath[f.Path] = true
			cleanups = append(cleanups, f.HistoryCleanup)
		}
	}
	return guides, cleanups
}

// writeRemediation은 탐지에서 그치지 않고 실제 대응까지 이어지도록, 폐기 절차와
// 히스토리 정리 명령을 리포트 하단에 모아 보여준다.
func writeRemediation(w io.Writer, findings []finding.Finding) {
	guides, cleanups := collectRemediation(findings)

	if len(guides) == 0 && len(cleanups) == 0 {
		return
	}

	fmt.Fprintln(w, strings.Repeat("─", 60))
	fmt.Fprintln(w, "대응 방법")

	if len(cleanups) > 0 {
		fmt.Fprintln(w, "! 키를 지우기 전에 반드시 먼저 폐기하세요 — 히스토리에서 파일만 지워도")
		fmt.Fprintln(w, "  키 자체는 여전히 유효하고, 이미 어딘가에 클론되어 있을 수 있습니다.")
	}

	for _, g := range guides {
		fmt.Fprintf(w, "  [%s] %s\n", g.ruleID, g.text)
	}

	if len(cleanups) > 0 {
		fmt.Fprintln(w, "히스토리에서 제거 (폐기 완료 후 실행):")
		for _, cmd := range cleanups {
			fmt.Fprintf(w, "  %s\n", cmd)
		}
		fmt.Fprintln(w, "  (해당 파일을 히스토리 전체에서 제거합니다. 실행 후 원격에 강제 푸시하고")
		fmt.Fprintln(w, "   팀원 전원이 저장소를 다시 클론해야 합니다. 파일 전체가 아니라 값만")
		fmt.Fprintln(w, "   지우려면 git filter-repo --replace-text 규칙을 직접 구성하세요.)")
	}
}

func writeSummary(w io.Writer, r Report) {
	fmt.Fprintln(w, strings.Repeat("─", 60))
	fmt.Fprintf(w, "대상       %s\n", r.Target)
	fmt.Fprintf(w, "파일       %d개 스캔, %d개 제외\n", r.Summary.FilesScanned, r.Summary.FilesSkipped)
	if r.Summary.CommitsScanned > 0 {
		fmt.Fprintf(w, "커밋       %d개 스캔\n", r.Summary.CommitsScanned)
	}

	line := fmt.Sprintf("%d건", r.Summary.Findings)
	if breakdown := SeverityBreakdown(r.Summary.BySeverity); breakdown != "" {
		line += " (" + breakdown + ")"
	}
	fmt.Fprintf(w, "탐지       %s\n", line)
	fmt.Fprintf(w, "오탐 필터  %d건 제외\n", r.Summary.FilteredOut)
	if r.Summary.BaselineKnown > 0 {
		fmt.Fprintf(w, "baseline   %d건 제외 (이미 알려진 시크릿)\n", r.Summary.BaselineKnown)
	}
	writeValidationSummary(w, r.Summary.Validation)
	fmt.Fprintf(w, "소요       %dms\n", r.Summary.DurationMS)
}

func writeValidationSummary(w io.Writer, v *ValidationSummary) {
	if v == nil {
		return
	}

	fmt.Fprintf(w, "키 검증    유효 %d, 폐기됨 %d, 검증불가 %d",
		v.Valid, v.Revoked, v.Unknown)
	if v.Unsupported > 0 {
		fmt.Fprintf(w, " (검증기 없는 룰 %d건 제외)", v.Unsupported)
	}
	fmt.Fprintln(w)

	if v.Offline {
		fmt.Fprintln(w, "           ! 네트워크에 연결하지 못해 일부 검증을 건너뛰었습니다")
	}
	if v.Valid > 0 {
		fmt.Fprintf(w, "           ! 살아있는 키 %d건 — 파일을 지우기 전에 먼저 폐기하세요\n", v.Valid)
	}
}

// SeverityBreakdown은 "critical 2, high 1" 형태의 심각도 분포 문자열을 만든다.
// 리포트와 CLI 요약이 같은 표기를 쓰도록 공개한다.
func SeverityBreakdown(counts map[string]int) string {
	order := []config.Severity{
		config.SeverityCritical, config.SeverityHigh,
		config.SeverityMedium, config.SeverityLow,
	}

	var parts []string
	for _, s := range order {
		if n := counts[string(s)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, n))
		}
	}
	return strings.Join(parts, ", ")
}

// annotation은 신뢰도와, 묶인 결과일 때 그 사실을 덧붙인다.
// 위치가 과거 커밋을 가리키면 지금도 남아있는지가 대응 판단에 중요하므로 함께 표시한다.
func annotation(f finding.Finding) string {
	s := fmt.Sprintf("신뢰도 %d", f.Confidence)
	if f.Occurrences > 1 {
		s += fmt.Sprintf(", %d곳", f.Occurrences)
	}
	if f.Commit != "" && f.InWorktree {
		s += ", 현재도 존재"
	}
	if label := validationLabel(f.Validation); label != "" {
		s += ", " + label
	}
	return s
}

func validationLabel(v *validator.Result) string {
	if v == nil {
		return ""
	}
	switch v.Status {
	case validator.StatusValid:
		return v.Provider + " 유효"
	case validator.StatusRevoked:
		return v.Provider + " 폐기됨"
	}
	return v.Provider + " 검증불가"
}

func location(f finding.Finding) string {
	if f.Commit != "" {
		return fmt.Sprintf("%s@%s:%d", f.Path, shortCommit(f.Commit), f.Line)
	}
	return fmt.Sprintf("%s:%d", f.Path, f.Line)
}

func shortCommit(hash string) string {
	if len(hash) > 7 {
		return hash[:7]
	}
	return hash
}

// severityLabel은 색상 코드가 정렬 폭 계산에 끼어들지 않도록
// 패딩을 먼저 계산한 뒤 색상을 입힌다.
func severityLabel(s config.Severity, color bool) string {
	const width = 8

	text := strings.ToUpper(string(s))
	pad := width - len(text)
	if pad < 0 {
		pad = 0
	}
	if color {
		text = colorize(s, text)
	}
	return text + strings.Repeat(" ", pad)
}

func colorize(s config.Severity, text string) string {
	const reset = "\033[0m"
	codes := map[config.Severity]string{
		config.SeverityCritical: "\033[1;31m",
		config.SeverityHigh:     "\033[31m",
		config.SeverityMedium:   "\033[33m",
		config.SeverityLow:      "\033[36m",
	}
	code, ok := codes[s]
	if !ok {
		return text
	}
	return code + text + reset
}

// IsTerminal은 출력이 파이프나 파일로 리다이렉트되었는지 판별한다.
// 리다이렉트된 출력에 ANSI 색상 코드가 섞이면 로그가 깨지므로 색상을 끈다.
func IsTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
