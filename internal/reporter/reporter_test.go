package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
	"github.com/whiteclover0542/secrethound/internal/validator"
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

// 검증을 켜지 않은 스캔에는 검증 관련 출력이 하나도 나오면 안 된다.
// "검증 안 함"과 "전부 검증불가"는 다른 상태다.
func TestValidationAbsentWhenNotRequested(t *testing.T) {
	r := Build(sampleInput())

	if r.Summary.Validation != nil {
		t.Errorf("검증하지 않았는데 요약이 채워짐: %+v", r.Summary.Validation)
	}

	var buf bytes.Buffer
	if err := WriteText(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "키 검증") {
		t.Errorf("검증하지 않은 스캔에 검증 줄이 나옴:\n%s", buf.String())
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "validation") {
		t.Errorf("JSON에 validation 키가 나오면 안 된다: %s", data)
	}
}

// 살아있다고 확인된 키는 심각도보다 앞서 맨 위로 온다.
// 검증을 켠 사람이 알고 싶은 것은 "지금 당장 폐기해야 할 키"이기 때문이다.
func TestValidatedFindingsSortLiveKeysFirst(t *testing.T) {
	in := sampleInput()
	in.Validated = true
	in.Validation = validator.Stats{Checked: 2, Valid: 1, Revoked: 1}

	// medium 이지만 살아있는 키
	in.Findings[0].Validation = &validator.Result{Status: validator.StatusValid, Provider: "GitHub"}
	// critical 이지만 이미 폐기된 키
	in.Findings[1].Validation = &validator.Result{Status: validator.StatusRevoked, Provider: "GitHub"}

	r := Build(in)

	if got := r.Findings[0].RuleID; got != "jwt" {
		t.Errorf("살아있는 키가 맨 위여야 한다: got %s", got)
	}
	if got := r.Findings[len(r.Findings)-1].Severity; got != config.SeverityCritical {
		t.Errorf("폐기된 키는 맨 뒤로 밀려야 한다: got %s", got)
	}
}

func TestWriteTextShowsValidationSummary(t *testing.T) {
	in := sampleInput()
	in.Validated = true
	in.Validation = validator.Stats{Checked: 2, Valid: 1, Revoked: 1, Unsupported: 2}
	in.Findings[0].Validation = &validator.Result{Status: validator.StatusValid, Provider: "GitHub"}
	in.Findings[1].Validation = &validator.Result{Status: validator.StatusRevoked, Provider: "Stripe"}

	var buf bytes.Buffer
	if err := WriteText(&buf, Build(in), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"키 검증",
		"유효 1, 폐기됨 1",
		"검증기 없는 룰 2건",
		"GitHub 유효",
		"Stripe 폐기됨",
		// 살아있는 키가 있으면 "지우기 전에 폐기부터"를 반드시 알려야 한다.
		// 히스토리만 지우면 키는 여전히 유효하다.
		"먼저 폐기하세요",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("출력에 %q 가 없음:\n%s", want, out)
		}
	}
}

func TestWriteTextWarnsWhenOffline(t *testing.T) {
	in := sampleInput()
	in.Validated = true
	in.Validation = validator.Stats{Checked: 4, Unknown: 4, Offline: true}

	var buf bytes.Buffer
	if err := WriteText(&buf, Build(in), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "네트워크에 연결하지 못해") {
		t.Errorf("오프라인 경고 누락:\n%s", buf.String())
	}
}
