package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiteclover0542/secrethound/internal/config"
)

func TestUnquotePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"감싸이지 않음", "b/docs/setup.md", "b/docs/setup.md"},
		{"한글 8진수", `"b/docs/\354\232\251\354\226\264\354\247\221.md"`, "b/docs/용어집.md"},
		{"따옴표 escape", `"b/a\"b.txt"`, `b/a"b.txt`},
		{"역슬래시 escape", `"b/a\\b.txt"`, `b/a\b.txt`},
		{"탭", `"b/a\tb.txt"`, "b/a\tb.txt"},
		// 형식이 어긋난 이스케이프는 경로를 조용히 망가뜨리지 않고 원문을 살린다.
		{"잘못된 8진수", `"b/a\9b.txt"`, `b/a\9b.txt`},
		{"빈 문자열", "", ""},
		{"따옴표 하나", `"`, `"`},
	}

	for _, tc := range tests {
		if got := unquotePath(tc.in); got != tc.want {
			t.Errorf("%s: unquotePath(%q) = %q, 기대값 %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// 한글 파일명은 git이 경로를 8진수로 이스케이프해 내보내기 때문에, 풀지 않으면
// 히스토리 쪽 경로가 워킹트리 쪽과 달라져 같은 시크릿이 두 건으로 갈라져 보고된다.
// 한국어 사용자가 주 대상인 도구라 실제 저장소로 확인한다.
func TestWalkHistoryHandlesNonASCIIPath(t *testing.T) {
	requireGit(t)

	repo := initRepo(t)
	const name = "문서/설정 안내.md"

	if err := os.MkdirAll(filepath.Join(repo, "문서"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, repo, name, "url: postgres://admin:s3cr3tpassw0rd@db.example.com:5432/app\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-m", "설정 문서 추가")

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
`))
	if err != nil {
		t.Fatal(err)
	}

	col := New(&rs.Filter)

	var paths []string
	if _, err := col.WalkHistory(repo, HistoryOptions{}, func(ch Change) error {
		paths = append(paths, ch.Path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if len(paths) == 0 {
		t.Fatal("히스토리에서 아무 변경도 읽지 못했습니다")
	}
	for _, p := range paths {
		if p != name {
			t.Errorf("경로 = %q, 기대값 %q (8진수 이스케이프가 풀리지 않았거나 b/ 가 남았다)", p, name)
		}
	}
}
