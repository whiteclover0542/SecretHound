package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestTargetName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"평범한 폴더", filepath.Join("C:", "projects", "myrepo"), "myrepo"},
		{"한글 폴더", filepath.Join("C:", "작업", "내 프로젝트"), "내 프로젝트"},
		{"끝에 구분자", filepath.Join("C:", "projects", "myrepo") + string(filepath.Separator), "myrepo"},
	}

	for _, tc := range tests {
		if got := targetName(tc.in); got != tc.want {
			t.Errorf("%s: targetName(%q) = %q, 기대값 %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// 파일 이름에 쓸 수 없는 문자가 남아 있으면 리포트 생성 자체가 실패한다.
func TestTargetNameHasNoPathSeparators(t *testing.T) {
	got := targetName(t.TempDir())
	if strings.ContainsAny(got, `<>:"/\|?*`) {
		t.Errorf("파일 이름에 쓸 수 없는 문자가 남음: %q", got)
	}
	if got == "" {
		t.Error("이름이 비어 있으면 리포트 이름이 폴더 구분을 잃는다")
	}
}

// 이전 결과를 덮어쓰지 않고 번호를 붙여 남겨야 한다.
func TestReportPathsAddsSuffixInsteadOfOverwriting(t *testing.T) {
	out := t.TempDir()
	target := filepath.Join(t.TempDir(), "myrepo")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}

	first, err := reportPaths(out, target)
	if err != nil {
		t.Fatal(err)
	}
	if base := filepath.Base(first[formatHTML]); base != "secrethound-report-myrepo.html" {
		t.Errorf("첫 리포트 이름 = %q", base)
	}

	// 실제로 파일을 만들어 두면 다음 호출은 번호를 붙여야 한다.
	for _, p := range first {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	second, err := reportPaths(out, target)
	if err != nil {
		t.Fatal(err)
	}
	if base := filepath.Base(second[formatHTML]); base != "secrethound-report-myrepo-1.html" {
		t.Errorf("두 번째 리포트 이름 = %q, 기대값 secrethound-report-myrepo-1.html", base)
	}
	if first[formatHTML] == second[formatHTML] {
		t.Error("같은 경로를 다시 돌려주면 이전 결과가 덮어써진다")
	}
}

// html 과 md 는 같은 검사에서 나온 짝이므로 번호가 어긋나면 안 된다.
func TestReportPathsKeepsFormatsInSync(t *testing.T) {
	out := t.TempDir()
	target := filepath.Join(t.TempDir(), "myrepo")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}

	// html 만 미리 만들어 둔다. md 는 비어 있어도 번호가 함께 올라가야 한다.
	if err := os.WriteFile(filepath.Join(out, "secrethound-report-myrepo.html"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths, err := reportPaths(out, target)
	if err != nil {
		t.Fatal(err)
	}

	htmlBase := strings.TrimSuffix(filepath.Base(paths[formatHTML]), formatExt[formatHTML])
	mdBase := strings.TrimSuffix(filepath.Base(paths[formatMD]), formatExt[formatMD])
	if htmlBase != mdBase {
		t.Errorf("형식별 이름이 어긋남: html=%q md=%q", htmlBase, mdBase)
	}
	if htmlBase != "secrethound-report-myrepo-1" {
		t.Errorf("이름 = %q, 기대값 secrethound-report-myrepo-1", htmlBase)
	}
}

// 서로 다른 폴더를 검사하면 리포트도 서로 다른 이름이어야 한다.
func TestReportPathsDistinguishesTargets(t *testing.T) {
	out := t.TempDir()
	parent := t.TempDir()

	var names []string
	for _, repo := range []string{"alpha", "beta"} {
		target := filepath.Join(parent, repo)
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		paths, err := reportPaths(out, target)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, filepath.Base(paths[formatHTML]))
	}

	if names[0] == names[1] {
		t.Errorf("서로 다른 폴더가 같은 리포트 이름을 씀: %v", names)
	}
	for i, want := range []string{"secrethound-report-alpha.html", "secrethound-report-beta.html"} {
		if names[i] != want {
			t.Errorf("리포트 이름 = %q, 기대값 %q", names[i], want)
		}
	}
}

// 저장소를 모아둔 폴더를 지정하면 그 아래 저장소들을 대신 검사해야 한다.
func TestExpandTargetsFindsChildRepos(t *testing.T) {
	requireGitBinary(t)

	parent := t.TempDir()
	made := []string{"alpha", "beta"}
	for _, name := range made {
		initRepoAt(t, filepath.Join(parent, name))
	}
	// 저장소가 아닌 폴더는 대상에 들어가면 안 된다.
	if err := os.MkdirAll(filepath.Join(parent, "not-a-repo"), 0o755); err != nil {
		t.Fatal(err)
	}

	targets, err := expandTargets([]string{parent})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != len(made) {
		t.Fatalf("대상 %d개 = %v, 기대값 %d개", len(targets), targets, len(made))
	}
	for i, name := range made {
		if filepath.Base(targets[i]) != name {
			t.Errorf("대상[%d] = %q, 기대값 %q", i, targets[i], name)
		}
	}
}

// 저장소를 직접 지정하면 그 저장소만 검사한다 (아래를 뒤지지 않는다).
func TestExpandTargetsKeepsRepoItself(t *testing.T) {
	requireGitBinary(t)

	repo := filepath.Join(t.TempDir(), "solo")
	initRepoAt(t, repo)
	initRepoAt(t, filepath.Join(repo, "nested"))

	targets, err := expandTargets([]string{repo})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != repo {
		t.Errorf("대상 = %v, 기대값 [%s]", targets, repo)
	}
}

// 같은 폴더를 두 번 지정해도 한 번만 검사해야 한다.
func TestExpandTargetsDeduplicates(t *testing.T) {
	requireGitBinary(t)

	repo := filepath.Join(t.TempDir(), "dup")
	initRepoAt(t, repo)

	targets, err := expandTargets([]string{repo, repo})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Errorf("대상 = %v, 기대값 1개", targets)
	}
}

// 저장소도 아니고 아래에 저장소도 없으면, 그 폴더의 파일만 검사한다.
func TestExpandTargetsFallsBackToPlainFolder(t *testing.T) {
	dir := t.TempDir()

	targets, err := expandTargets([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != dir {
		t.Errorf("대상 = %v, 기대값 [%s]", targets, dir)
	}
}

// 저장소를 같은 이름의 폴더로 한 번 감싸두는 배치가 흔하다 (projects/myapp/myapp).
// 한 단계만 내려가면 이런 저장소를 통째로 놓친다 — 실제로 그 버그가 있었다.
func TestExpandTargetsFindsNestedRepos(t *testing.T) {
	requireGitBinary(t)

	parent := t.TempDir()
	initRepoAt(t, filepath.Join(parent, "직속저장소"))            // 1단계
	initRepoAt(t, filepath.Join(parent, "wrapper", "안쪽저장소")) // 2단계
	initRepoAt(t, filepath.Join(parent, "a", "b", "깊은저장소"))  // 3단계

	targets, err := expandTargets([]string{parent})
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, tgt := range targets {
		names = append(names, filepath.Base(tgt))
	}
	sort.Strings(names)

	want := []string{"깊은저장소", "안쪽저장소", "직속저장소"}
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("찾은 저장소 = %v, 기대값 %v", names, want)
	}
}

// 깊이 제한이 없으면 홈 디렉토리를 고른 순간 디스크 전체를 훑게 된다.
func TestExpandTargetsStopsAtDepthLimit(t *testing.T) {
	requireGitBinary(t)

	parent := t.TempDir()
	deep := filepath.Join(parent, "a", "b", "c", "d", "너무깊은저장소")
	initRepoAt(t, deep)

	targets, err := expandTargets([]string{parent})
	if err != nil {
		t.Fatal(err)
	}
	for _, tgt := range targets {
		if filepath.Base(tgt) == "너무깊은저장소" {
			t.Errorf("깊이 제한(%d)을 넘는 저장소가 잡힘: %s", maxSearchDepth, tgt)
		}
	}
}

// 저장소 안의 서브모듈까지 따로 잡으면 같은 파일을 두 번 검사하게 된다.
func TestExpandTargetsDoesNotDescendIntoRepos(t *testing.T) {
	requireGitBinary(t)

	parent := t.TempDir()
	outer := filepath.Join(parent, "바깥저장소")
	initRepoAt(t, outer)
	initRepoAt(t, filepath.Join(outer, "안쪽"))

	targets, err := expandTargets([]string{parent})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || filepath.Base(targets[0]) != "바깥저장소" {
		t.Errorf("대상 = %v, 기대값 [바깥저장소]", targets)
	}
}

// node_modules 같은 폴더는 크고 깊은데 그 안에 사용자의 저장소가 있을 리 없다.
func TestSkipSearchDir(t *testing.T) {
	skipped := []string{"node_modules", "vendor", ".git", ".idea", "dist", "build", "NODE_MODULES"}
	for _, name := range skipped {
		if !skipSearchDir(name) {
			t.Errorf("%q 는 건너뛰어야 한다", name)
		}
	}
	for _, name := range []string{"src", "myrepo", "내 프로젝트"} {
		if skipSearchDir(name) {
			t.Errorf("%q 는 들어가 봐야 한다", name)
		}
	}
}
