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
	Validated      bool
	Validation     validator.Stats
	Duration       time.Duration
}

func Build(in Input) Report {
	findings := append([]finding.Finding(nil), in.Findings...)
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
	for _, f := range findings {
		bySeverity[string(f.Severity)]++
	}

	summary := Summary{
		FilesScanned:   in.FilesScanned,
		FilesSkipped:   in.FilesSkipped,
		CommitsScanned: in.CommitsScanned,
		Findings:       len(findings),
		FilteredOut:    in.FilteredOut,
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
	return nil
}

func writeSummary(w io.Writer, r Report) {
	fmt.Fprintln(w, strings.Repeat("─", 60))
	fmt.Fprintf(w, "대상       %s\n", r.Target)
	fmt.Fprintf(w, "파일       %d개 스캔, %d개 제외\n", r.Summary.FilesScanned, r.Summary.FilesSkipped)
	if r.Summary.CommitsScanned > 0 {
		fmt.Fprintf(w, "커밋       %d개 스캔\n", r.Summary.CommitsScanned)
	}

	line := fmt.Sprintf("%d건", r.Summary.Findings)
	if breakdown := severityBreakdown(r.Summary.BySeverity); breakdown != "" {
		line += " (" + breakdown + ")"
	}
	fmt.Fprintf(w, "탐지       %s\n", line)
	fmt.Fprintf(w, "오탐 필터  %d건 제외\n", r.Summary.FilteredOut)
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

func severityBreakdown(counts map[string]int) string {
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
