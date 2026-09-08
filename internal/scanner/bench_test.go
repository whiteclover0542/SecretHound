package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/config"
)

// docs/progress.md #4의 "파일 트리 스캔은 워커 풀로 약 2배, 히스토리 스캔은
// git log 자체가 병목이라 효과 미미"라는 결론은 수동으로 클론한 express.js로
// 한 번 측정한 결과였다. 이 벤치마크는 그 결론을 저장소 밖 의존 없이 재현 가능한
// 형태로 남긴다 — `go test -bench=. ./internal/scanner/...` 로 누구나 다시 확인할 수 있다.
// 절대 시간은 머신마다 다르므로, 봐야 할 것은 Workers=1과 자동(worker=0) 사이의 비율이다.
//
// 재현해보니 절반만 재현됐다: 히스토리 쪽 결론(효과 미미)은 그대로 확인됐지만,
// 파일 트리 쪽 "약 2배"는 이 벤치마크에서 나오지 않는다 — CPU 부하를 키워도
// 10~15% 수준에 그친다. 유력한 원인은 이 벤치마크가 매 반복마다 같은 임시
// 디렉토리를 재사용해 OS 파일 캐시가 데워진 상태로 측정된다는 점이다.
// 원래 측정은 방금 클론한 실제 레포(콜드 캐시, Windows 안티바이러스의 파일별
// 스캔 오버헤드 포함 가능성)를 대상으로 했다 — 그 경우 이득은 CPU 병렬화가
// 아니라 "파일을 읽는 동안 다음 파일의 매칭을 겹쳐 돌리는" I/O 오버랩에서
// 왔을 가능성이 크다. 상세 논의는 docs/평가지표.md 12번 항목 참조.

// benchGit은 dir에서 git 서브커맨드를 실행한다. 실패하면 벤치마크를 중단시킨다.
func benchGit(b *testing.B, dir string, args ...string) {
	b.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("git %s 실패: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// buildBenchRepo는 files개의 파일을 만든다. history가 true면 파일마다 커밋을 하나씩
// 쌓아 git log가 파싱할 실제 히스토리를 만든다 (커밋 수 = files).
func buildBenchRepo(b *testing.B, files int, history bool) string {
	b.Helper()
	dir := b.TempDir()

	if history {
		if _, err := exec.LookPath("git"); err != nil {
			b.Skip("git이 설치되어 있지 않아 건너뜀")
		}
		benchGit(b, dir, "init")
		benchGit(b, dir, "config", "user.email", "bench@example.com")
		benchGit(b, dir, "config", "user.name", "bench")
	}

	for i := 0; i < files; i++ {
		name := fmt.Sprintf("file%04d.go", i)
		content := benchFileContent(i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			b.Fatal(err)
		}
		if history {
			benchGit(b, dir, "add", name)
			benchGit(b, dir, "commit", "-m", "add "+name)
		}
	}

	return dir
}

// benchFileContent는 실제 코드처럼 보통 줄과 시크릿이 섞인 파일을 만든다.
// 전부 시크릿인 최악의 경우가 아니라, 평가 코퍼스나 실제 레포와 비슷한 밀도를 노렸다.
// 파일당 400줄은 정규식 매칭의 CPU 부하가 채널 통신 비용에 묻히지 않을 만큼
// 크게 잡은 것이다 — 150줄에서는 워커 수에 따른 차이가 노이즈 수준(4%)이었고,
// 400줄로 올리자 그나마 뚜렷한 차이(14%)가 드러났다.
func benchFileContent(seed int) string {
	var sb strings.Builder
	for line := 0; line < 400; line++ {
		if line%10 == 5 {
			fmt.Fprintf(&sb, "const token = \"ghp_%036d\"\n", seed*1000+line)
		} else {
			fmt.Fprintf(&sb, "func noop%d_%d(x int, y string) bool { return x > 0 && y != \"\" }\n", seed, line)
		}
	}
	return sb.String()
}

func benchmarkWorktree(b *testing.B, workers int) {
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		b.Fatal(err)
	}
	dir := buildBenchRepo(b, 800, false)

	b.ResetTimer()
	for range b.N {
		if _, err := Run(b.Context(), rs, Options{Target: dir, Workers: workers}); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkHistory(b *testing.B, workers int) {
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		b.Fatal(err)
	}
	dir := buildBenchRepo(b, 150, true)

	b.ResetTimer()
	for range b.N {
		if _, err := Run(b.Context(), rs, Options{Target: dir, History: true, Workers: workers}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanWorktree_Workers1과 BenchmarkScanWorktree_Auto를 나란히 돌리면
// 파일 트리 스캔에서 워커 풀이 실제로 이득인지 확인할 수 있다.
func BenchmarkScanWorktree_Workers1(b *testing.B) { benchmarkWorktree(b, 1) }
func BenchmarkScanWorktree_Auto(b *testing.B)     { benchmarkWorktree(b, 0) }

// 히스토리 쪽은 git log 파싱이 병목이라는 게 progress.md의 결론이다 —
// 두 벤치마크의 시간이 비슷하게 나오면(워커를 늘려도 빨라지지 않으면) 그 결론이 재현된 것이다.
func BenchmarkScanHistory_Workers1(b *testing.B) { benchmarkHistory(b, 1) }
func BenchmarkScanHistory_Auto(b *testing.B)     { benchmarkHistory(b, 0) }
