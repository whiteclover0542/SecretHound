package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiteclover0542/secrethound/internal/config"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s 실패: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// 워킹트리에서는 이미 지워졌지만 커밋 히스토리에는 남아있는 시크릿을 찾아내는지 검증한다.
// 이 도구의 핵심 가치라서 실제 git 레포를 만들어 확인한다.
func TestWalkHistoryFindsDeletedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git이 설치되어 있지 않아 건너뜀")
	}

	repo := t.TempDir()
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@example.com")
	git(t, repo, "config", "user.name", "tester")

	const secret = "ghp_9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXk"
	writeFile(t, repo, "config.js", "const a = 1;\nconst token = \""+secret+"\";\n")
	git(t, repo, "add", "config.js")
	git(t, repo, "commit", "-m", "실수로 토큰 커밋")

	// 시크릿을 지운다. 이제 워킹트리에는 없지만 히스토리에는 남아있다.
	writeFile(t, repo, "config.js", "const a = 1;\nconst token = process.env.TOKEN;\n")
	git(t, repo, "add", "config.js")
	git(t, repo, "commit", "-m", "토큰 제거")

	rs, err := config.Parse([]byte(`
version: 1
rules:
  - id: dummy
    description: 테스트용
    severity: low
    regex: 'never-match-xyz'
    secret_group: 0
filter:
  exclude_paths: []
  exclude_extensions: []
`))
	if err != nil {
		t.Fatal(err)
	}

	var changes []Change
	stats, err := New(&rs.Filter).WalkHistory(repo, HistoryOptions{}, func(ch Change) error {
		changes = append(changes, ch)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkHistory 실패: %v", err)
	}

	if stats.Commits != 2 {
		t.Errorf("스캔한 커밋 수 = %d, 기대값 2", stats.Commits)
	}

	var hit *Change
	for i := range changes {
		if strings.Contains(changes[i].Line, secret) {
			hit = &changes[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("히스토리에서 삭제된 시크릿을 찾지 못함. 수집된 변경: %+v", changes)
	}

	if hit.Path != "config.js" {
		t.Errorf("Path = %q, 기대값 config.js", hit.Path)
	}
	if hit.LineNo != 2 {
		t.Errorf("LineNo = %d, 기대값 2", hit.LineNo)
	}
	if hit.Author != "tester" {
		t.Errorf("Author = %q, 기대값 tester", hit.Author)
	}
	if hit.Commit == "" || hit.Date == "" {
		t.Errorf("커밋 해시/날짜가 비어 있음: %+v", hit)
	}
}

func TestWalkHistoryRejectsNonRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git이 설치되어 있지 않아 건너뜀")
	}

	_, err := newTestCollector(t).WalkHistory(t.TempDir(), HistoryOptions{}, func(Change) error {
		return nil
	})
	if err == nil {
		t.Error("git 레포가 아닌 경로에서 에러가 발생하지 않음")
	}
}

func TestParseHunkStart(t *testing.T) {
	cases := map[string]int{
		"@@ -12,3 +34,5 @@":             34,
		"@@ -0,0 +1 @@":                 1,
		"@@ -1,2 +7,0 @@ func main() {": 7,
		"잘못된 형식":                        1,
	}
	for input, want := range cases {
		if got := parseHunkStart(input); got != want {
			t.Errorf("parseHunkStart(%q) = %d, 기대값 %d", input, got, want)
		}
	}
}
