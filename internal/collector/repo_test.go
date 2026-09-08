package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git이 설치되어 있지 않아 건너뜀")
	}
}

// initRepo는 커밋이 없는 빈 저장소를 만든다.
func initRepo(t *testing.T) string {
	t.Helper()

	repo := t.TempDir()
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@example.com")
	git(t, repo, "config", "user.name", "tester")
	return repo
}

// git init 직후에는 커밋이 없어 git log 가 128로 실패한다. 검사할 히스토리가
// 없는 것은 오류가 아니므로, 스캔 전체가 중단되지 않고 0개 커밋으로 끝나야 한다.
func TestWalkHistoryEmptyRepoIsNotAnError(t *testing.T) {
	requireGit(t)

	repo := initRepo(t)
	writeFile(t, repo, "a.txt", "hello\n")

	stats, err := newTestCollector(t).WalkHistory(repo, HistoryOptions{}, func(Change) error {
		t.Error("커밋이 없는데 변경 내역이 전달됨")
		return nil
	})
	if err != nil {
		t.Fatalf("커밋 없는 저장소에서 오류가 발생함: %v", err)
	}
	if stats.Commits != 0 {
		t.Errorf("커밋 수 = %d, 기대값 0", stats.Commits)
	}
}

func TestHasCommits(t *testing.T) {
	requireGit(t)

	repo := initRepo(t)
	if HasCommits(repo) {
		t.Error("커밋이 없는데 있다고 판정됨")
	}

	writeFile(t, repo, "a.txt", "hello\n")
	git(t, repo, "add", "a.txt")
	git(t, repo, "commit", "-m", "first")

	if !HasCommits(repo) {
		t.Error("커밋이 있는데 없다고 판정됨")
	}
}

// 저장소의 하위 폴더는 저장소 최상위가 아니다. 이 구분이 없으면 사용자가 고른
// 폴더와 무관한 상위 저장소의 히스토리를 검사하게 된다.
func TestIsRepoRootOnlyAtTop(t *testing.T) {
	requireGit(t)

	repo := initRepo(t)
	sub := filepath.Join(repo, "src")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	if !IsRepoRoot(repo) {
		t.Errorf("저장소 최상위(%s)가 최상위로 판정되지 않음", repo)
	}
	if IsRepoRoot(sub) {
		t.Errorf("하위 폴더(%s)가 저장소 최상위로 판정됨", sub)
	}

	// 하위 폴더에서도 소속 저장소는 찾을 수 있어야 한다.
	if got := RepoRoot(sub); !sameDir(got, repo) {
		t.Errorf("RepoRoot(%s) = %s, 기대값 %s", sub, got, repo)
	}
}

func TestRepoRootEmptyForNonRepo(t *testing.T) {
	requireGit(t)

	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))

	if got := RepoRoot(dir); got != "" {
		t.Errorf("저장소가 아닌 경로의 RepoRoot = %q, 기대값 빈 문자열", got)
	}
	if IsRepoRoot(dir) {
		t.Error("저장소가 아닌 경로가 저장소 최상위로 판정됨")
	}
}
