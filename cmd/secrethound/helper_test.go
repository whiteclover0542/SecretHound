package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func requireGitBinary(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git이 설치되어 있지 않아 건너뜀")
	}
}

// initRepoAt은 커밋이 하나 있는 git 저장소를 만든다.
// 커밋을 넣는 이유는 히스토리 판단 경로까지 실제 저장소로 확인하기 위해서다.
func initRepoAt(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", path}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v 실패: %v\n%s", args, err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "tester")

	if err := os.WriteFile(filepath.Join(path, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "a.txt")
	run("commit", "-m", "first")
}
