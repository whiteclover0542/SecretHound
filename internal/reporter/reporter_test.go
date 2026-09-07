package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

func sampleInput() Input {
	return Input{
		Target:       ".",
		Version:      "test",
		FilesScanned: 10,
		FilesSkipped: 2,
		FilteredOut:  3,
		Duration:     15 * time.Millisecond,
		Findings: []finding.Finding{
			{RuleID: "jwt", Severity: config.SeverityMedium, Path: "b.go", Line: 5, Secret: "raw-medium", Masked: "med***"},
			{RuleID: "github-pat", Severity: config.SeverityCritical, Path: "z.go", Line: 1, Secret: "raw-critical", Masked: "cri***"},
			{RuleID: "aws-access-key-id", Severity: config.SeverityHigh, Path: "a.go", Line: 9, Secret: "raw-high", Masked: "hig***"},
			{RuleID: "github-pat", Severity: config.SeverityCritical, Path: "a.go", Line: 3, Secret: "raw-critical2", Masked: "cr2***"},
		},
	}
}

func TestBuildSortsBySeverityThenLocation(t *testing.T) {
	r := Build(sampleInput())

	var got []string
	for _, f := range r.Findings {
		got = append(got, string(f.Severity)+":"+f.Path)
	}
	want := []string{"critical:a.go", "critical:z.go", "high:a.go", "medium:b.go"}

	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("정렬 결과 = %v, 기대값 = %v", got, want)
	}
	if r.Summary.BySeverity["critical"] != 2 {
		t.Errorf("critical 집계 = %d, 기대값 2", r.Summary.BySeverity["critical"])
	}
	if r.Summary.Findings != 4 || r.Summary.FilteredOut != 3 {
		t.Errorf("요약 통계 불일치: %+v", r.Summary)
	}
}

// Build가 입력 슬라이스를 정렬하며 훼손하면 호출자 쪽 데이터가 바뀌므로 확인한다.
func TestBuildDoesNotMutateInput(t *testing.T) {
	in := sampleInput()
	first := in.Findings[0].RuleID

	Build(in)

	if in.Findings[0].RuleID != first {
		t.Errorf("입력 슬라이스가 정렬로 변경됨: %s → %s", first, in.Findings[0].RuleID)
	}
}

// 리포트 파일이 2차 유출 경로가 되면 안 되므로 원본 값이 절대 나가지 않아야 한다.
func TestWriteJSONExcludesRawSecret(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Build(sampleInput())); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(buf.String(), "raw-critical") {
		t.Error("JSON 출력에 마스킹되지 않은 원본 시크릿이 포함됨")
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON 파싱 실패: %v", err)
	}
	if len(decoded.Findings) != 4 {
		t.Errorf("탐지 건수 = %d, 기대값 4", len(decoded.Findings))
	}
}

func TestWriteTextNoColorHasNoANSI(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, Build(sampleInput()), false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Error("색상 비활성화 상태에서 ANSI 코드가 출력됨")
	}
	if !strings.Contains(out, "z.go:1") || !strings.Contains(out, "CRITICAL") {
		t.Errorf("출력에 위치/심각도가 누락됨:\n%s", out)
	}
}

func TestWriteTextEmpty(t *testing.T) {
	var buf bytes.Buffer
	in := sampleInput()
	in.Findings = nil

	if err := WriteText(&buf, Build(in), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "탐지된 시크릿이 없습니다") {
		t.Errorf("빈 결과 안내 문구 누락:\n%s", buf.String())
	}
}
