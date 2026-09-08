package reporter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiteclover0542/secrethound/internal/validator"
)

// dashboardTemplate은 실제 배포되는 페이지를 그대로 읽어온다. 테스트용 가짜
// 템플릿을 쓰면 페이지에서 주입 자리를 지웠을 때 테스트가 알아채지 못한다.
func dashboardTemplate(t *testing.T) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("..", "..", "web", "dashboard.html"))
	if err != nil {
		t.Fatalf("대시보드 템플릿을 읽지 못했습니다: %v", err)
	}
	return b
}

// embeddedJSON은 결과 HTML에서 심어진 리포트 블록만 잘라낸다.
func embeddedJSON(t *testing.T, html string) string {
	t.Helper()

	const open = `<script id="secrethound-report" type="application/json">`

	i := strings.Index(html, open)
	if i < 0 {
		t.Fatal("심어진 리포트 블록을 찾지 못했습니다")
	}
	body := html[i+len(open):]

	end := strings.Index(body, "</script>")
	if end < 0 {
		t.Fatal("리포트 블록이 닫히지 않았습니다")
	}
	return body[:end]
}

func TestWriteHTMLEmbedsRenderableReport(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, Build(sampleInput()), dashboardTemplate(t)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// 주입 자리는 소비되어야 하고, 페이지의 나머지 기능은 그대로 남아야 한다.
	if strings.Contains(out, reportSlot) {
		t.Error("주입 자리 주석이 그대로 남아있음")
	}
	if !strings.Contains(out, `id="dropzone"`) {
		t.Error("대시보드 원본 마크업이 사라짐")
	}

	var decoded Report
	if err := json.Unmarshal([]byte(embeddedJSON(t, out)), &decoded); err != nil {
		t.Fatalf("심어진 리포트가 유효한 JSON이 아님: %v", err)
	}
	if len(decoded.Findings) != 4 || decoded.Summary.Findings != 4 {
		t.Errorf("심어진 리포트의 탐지 건수 = %d, 기대값 4", len(decoded.Findings))
	}
}

// 스캔 대상 저장소의 파일 경로가 그대로 페이지에 실린다. 경로에 스크립트 태그를
// 심어두면 리포트를 여는 것만으로 코드가 실행될 수 있으므로 그 경로가 막혀 있는지
// 확인한다. json.Encoder의 SetEscapeHTML이 이 방어를 담당한다.
func TestWriteHTMLNeutralizesScriptInPath(t *testing.T) {
	const evil = `a</script><script>alert(1)</script>.go`

	in := sampleInput()
	in.Findings[0].Path = evil

	var buf bytes.Buffer
	if err := WriteHTML(&buf, Build(in), dashboardTemplate(t)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if strings.Contains(out, "<script>alert(1)") {
		t.Error("경로에 들어있던 스크립트 태그가 페이지에 그대로 실렸음")
	}

	// 이스케이프가 깨졌다면 블록이 첫 번째 종료 태그에서 잘려 JSON 파싱부터 실패한다.
	var decoded Report
	if err := json.Unmarshal([]byte(embeddedJSON(t, out)), &decoded); err != nil {
		t.Fatalf("심어진 리포트가 유효한 JSON이 아님: %v", err)
	}

	var found bool
	for _, f := range decoded.Findings {
		if f.Path == evil {
			found = true
		}
	}
	if !found {
		t.Error("경로 값이 이스케이프 과정에서 손상됨")
	}
}

func TestWriteHTMLExcludesRawSecret(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, Build(sampleInput()), dashboardTemplate(t)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "raw-critical") {
		t.Error("HTML 출력에 마스킹되지 않은 원본 시크릿이 포함됨")
	}
}

// 주입 자리가 사라진 템플릿을 조용히 그대로 내보내면 사용자는 아무것도 뜨지 않는
// 빈 대시보드를 받고 원인을 알 수 없다. 그래서 오류로 세운다.
func TestWriteHTMLFailsWithoutSlot(t *testing.T) {
	var buf bytes.Buffer

	err := WriteHTML(&buf, Build(sampleInput()), []byte("<html><body>자리 없음</body></html>"))
	if err == nil {
		t.Fatal("주입 자리가 없는 템플릿인데 오류가 나지 않음")
	}
	if buf.Len() != 0 {
		t.Errorf("실패했는데 출력이 쓰임: %q", buf.String())
	}
}

func TestWriteMarkdownHasSummaryAndFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(sampleInput())); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	want := []string{
		"# secrethound 검사 결과",
		"## 한눈에 보기",
		"## 탐지 목록",
		"4건",
		"`z.go:1`",
		"CRITICAL",
		"표 보는 법",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("마크다운에 %q 가 없음:\n%s", w, out)
		}
	}
}

func TestWriteMarkdownExcludesRawSecret(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(sampleInput())); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "raw-critical") {
		t.Error("마크다운 출력에 마스킹되지 않은 원본 시크릿이 포함됨")
	}
}

func TestWriteMarkdownEmpty(t *testing.T) {
	in := sampleInput()
	in.Findings = nil

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "찾지 못했습니다") {
		t.Errorf("빈 결과 안내 문구 누락:\n%s", out)
	}
	// 히스토리를 보지 않았다면 "깨끗하다"가 아니라 "여기까지만 봤다"가 정확하다.
	if !strings.Contains(out, "과거 커밋에 남아있는 키") {
		t.Errorf("현재 파일만 검사했다는 단서가 없음:\n%s", out)
	}
	if strings.Contains(out, "## 탐지 목록") {
		t.Errorf("탐지가 없는데 목록 절이 나옴:\n%s", out)
	}
}

// 경로와 룰 문구는 스캔 대상 저장소에서 오는 값이라 표를 깨는 문자가 섞일 수 있다.
func TestWriteMarkdownEscapesTableCells(t *testing.T) {
	in := sampleInput()
	in.Findings[0].Path = "we|rd/pa`th.go"

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}

	var row string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "rd/pa") {
			row = line
		}
	}
	if row == "" {
		t.Fatalf("해당 행을 찾지 못함:\n%s", buf.String())
	}

	// 파이프가 이스케이프되어야 셀이 하나 더 생기지 않는다.
	if !strings.Contains(row, `we\|rd`) {
		t.Errorf("표의 파이프가 이스케이프되지 않음: %s", row)
	}
	// 백틱이 든 값은 더 긴 구분자로 감싸야 코드 스팬이 중간에 끊기지 않는다.
	if !strings.Contains(row, "``") {
		t.Errorf("백틱이 든 값의 코드 스팬 구분자가 늘어나지 않음: %s", row)
	}
}

func TestWriteMarkdownRemediationOncePerRule(t *testing.T) {
	in := sampleInput()
	in.Findings[1].Remediation = "GitHub PAT를 Delete 하세요" // z.go, github-pat
	in.Findings[3].Remediation = "GitHub PAT를 Delete 하세요" // a.go, 같은 룰
	in.Findings[1].Commit = "deadbeef"

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if n := strings.Count(out, "GitHub PAT를 Delete 하세요"); n != 1 {
		t.Errorf("같은 룰의 안내가 %d번 나옴 (1번이어야 함):\n%s", n, out)
	}
	if !strings.Contains(out, "git filter-repo --path 'z.go' --invert-paths") {
		t.Errorf("히스토리 정리 명령 누락:\n%s", out)
	}
	if !strings.Contains(out, "순서가 중요합니다") {
		t.Errorf("폐기 우선 경고 누락:\n%s", out)
	}
}

func TestWriteMarkdownOmitsRemediationWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(sampleInput())); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "## 대응 방법") {
		t.Errorf("안내할 내용이 없는데 대응 방법 절이 출력됨:\n%s", buf.String())
	}
}

func TestWriteMarkdownShowsValidation(t *testing.T) {
	in := sampleInput()
	in.Validated = true
	in.Validation = validator.Stats{Checked: 2, Valid: 1, Revoked: 1, Unsupported: 2}
	in.Findings[0].Validation = &validator.Result{
		Status:   validator.StatusValid,
		Provider: "GitHub",
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "키 생존 확인") {
		t.Errorf("검증 요약 줄 누락:\n%s", out)
	}
	if !strings.Contains(out, "지금도 살아있는 키 1건") {
		t.Errorf("살아있는 키 경고 누락:\n%s", out)
	}
	if !strings.Contains(out, "GitHub 유효") {
		t.Errorf("개별 검증 결과 누락:\n%s", out)
	}
}

// 검증하지 않은 스캔에는 검증 관련 문구가 하나도 나오면 안 된다.
func TestWriteMarkdownOmitsValidationWhenNotRequested(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(sampleInput())); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "키 생존 확인") {
		t.Errorf("검증하지 않은 스캔에 검증 줄이 나옴:\n%s", buf.String())
	}
}

func TestWriteMarkdownHistoryNote(t *testing.T) {
	in := sampleInput()
	in.CommitsScanned = 12
	in.Findings[1].Commit = "deadbeef"
	in.Findings[1].InWorktree = false
	in.Findings[3].Commit = "cafebabe"
	in.Findings[3].InWorktree = true

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "| 검사한 커밋 | 12개 |") {
		t.Errorf("커밋 수 요약 누락:\n%s", out)
	}
	if !strings.Contains(out, "과거 커밋에만 남아있음") {
		t.Errorf("히스토리에만 남은 값에 대한 문구 누락:\n%s", out)
	}
	if !strings.Contains(out, "현재 파일에도 남아있음") {
		t.Errorf("워킹트리에도 남은 값에 대한 문구 누락:\n%s", out)
	}
}

func TestMarkdownCellEscaping(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"파이프", "a|b", `a\|b`},
		{"개행", "a\nb", "a b"},
		{"CRLF", "a\r\nb", "a b"},
		{"평범", "a.go", "a.go"},
	}

	for _, tc := range tests {
		if got := mdCell(tc.in); got != tc.want {
			t.Errorf("%s: mdCell(%q) = %q, 기대값 %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestMarkdownCodeSpan(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"평범", "a.go", "`a.go`"},
		{"백틱 포함", "a`b", "``a`b``"},
		{"백틱으로 끝남", "ab`", "`` ab` ``"},
		{"백틱으로 시작", "`ab", "`` `ab ``"},
	}

	for _, tc := range tests {
		if got := mdCode(tc.in); got != tc.want {
			t.Errorf("%s: mdCode(%q) = %q, 기대값 %q", tc.name, tc.in, got, tc.want)
		}
	}
}
