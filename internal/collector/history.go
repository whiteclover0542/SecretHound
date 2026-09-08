package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// go-git 대신 git 명령어를 직접 호출한다.
// 대상이 git 레포인 이상 git은 이미 설치되어 있고, 대형 레포에서 diff 순회 성능이
// 순수 Go 구현보다 크게 앞선다. 출력은 스트리밍으로 읽어 메모리 사용을 일정하게 유지한다.
const (
	// 커밋 헤더를 diff 본문과 구분하기 위한 마커. diff 텍스트에는 NUL이 나오지 않는다.
	commitMarker = "\x00"
	fieldSep     = "\x1f"

	// 실행 인자에는 NUL을 넣을 수 없어(exec가 EINVAL로 거부) git 포맷 지정자(%x00, %x1f)로
	// 출력 단계에서 위 바이트가 생성되도록 한다.
	prettyFormat = "--pretty=format:%x00%H%x1f%an%x1f%aI"

	// 미니파이 파일 등 초장문 라인 대응. 기본 64KB로는 스캔이 중단된다.
	maxLineSize = 1 << 20
)

// Change는 히스토리에서 발견된 "추가된 한 줄"이다.
// 삭제된 줄은 이미 존재했던 내용이므로 추가된 줄만 검사하면 중복 없이 전체 히스토리를 덮는다.
type Change struct {
	Commit string
	Author string
	Date   string
	Path   string
	Line   string
	LineNo int
}

type HistoryOptions struct {
	MaxCommits int
}

type HistoryStats struct {
	Commits int
	Lines   int
}

func (c *Collector) WalkHistory(root string, opts HistoryOptions, fn func(Change) error) (HistoryStats, error) {
	var stats HistoryStats

	if err := ensureGitRepo(root); err != nil {
		return stats, err
	}

	// git init 직후처럼 커밋이 하나도 없으면 git log 는 128로 실패한다.
	// 검사할 히스토리가 없는 것은 오류가 아니므로 빈 결과로 돌려준다.
	if !HasCommits(root) {
		return stats, nil
	}

	args := []string{
		"-C", root,
		// core.quotepath 기본값(true)은 경로의 비ASCII 바이트를 8진수 이스케이프로
		// 바꿔 내보낸다. 그러면 한글 파일명이 "docs/\354\232\251..." 형태로 나와
		// 워킹트리 쪽 경로와 달라지고, 같은 시크릿이 두 건으로 갈라져 보고된다.
		// 끄면 UTF-8 그대로 나온다. (특수문자가 든 경로는 여전히 따옴표로 감싸므로
		// unquotePath 로 한 번 더 푼다)
		"-c", "core.quotepath=false",
		"log",
		"--no-color",
		"--no-merges",
		"-p",
		"-U0", // 컨텍스트 줄은 검사 대상이 아니므로 받지 않는다
		prettyFormat,
	}
	if opts.MaxCommits > 0 {
		args = append(args, "-n", strconv.Itoa(opts.MaxCommits))
	}

	cmd := exec.Command("git", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stats, err
	}
	if err := cmd.Start(); err != nil {
		return stats, fmt.Errorf("git log 실행 실패: %w", err)
	}

	parseErr := c.parseLog(stdout, &stats, fn)

	// 콜백에서 중단했더라도 자식 프로세스를 반드시 정리한다.
	if parseErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return stats, parseErr
	}
	if err := cmd.Wait(); err != nil {
		return stats, fmt.Errorf("git log 실패: %w", err)
	}

	return stats, nil
}

func (c *Collector) parseLog(r io.Reader, stats *HistoryStats, fn func(Change) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	var (
		current Change
		lineNo  int
		skip    bool
	)

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, commitMarker):
			fields := strings.Split(strings.TrimPrefix(line, commitMarker), fieldSep)
			if len(fields) != 3 {
				continue
			}
			current = Change{Commit: fields[0], Author: fields[1], Date: fields[2]}
			stats.Commits++
			skip = true // 파일 헤더를 만나기 전까지는 검사 대상이 없다

		case strings.HasPrefix(line, "+++ "):
			path := strings.TrimPrefix(line, "+++ ")
			// 파일명에 공백이 있으면 git은 이름 뒤에 탭을 붙여 경계를 표시한다
			// (unified diff 관례). 탭 이후는 경로가 아니다.
			if tab := strings.IndexByte(path, '\t'); tab >= 0 {
				path = path[:tab]
			}
			if path == "/dev/null" {
				skip = true
				continue
			}
			// 따옴표를 먼저 풀어야 한다. 감싸인 상태에서는 경로가 큰따옴표로
			// 시작해 "b/" 접두사가 벗겨지지 않는다.
			current.Path = strings.TrimPrefix(unquotePath(path), "b/")
			skip = c.isSkippedHistoryPath(current.Path)

		case strings.HasPrefix(line, "@@"):
			lineNo = parseHunkStart(line)

		case strings.HasPrefix(line, "+"):
			if skip || current.Path == "" {
				continue
			}
			stats.Lines++
			change := current
			change.Line = strings.TrimPrefix(line, "+")
			change.LineNo = lineNo
			lineNo++

			if err := fn(change); err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("git log 출력 파싱 실패: %w", err)
	}
	return nil
}

func (c *Collector) isSkippedHistoryPath(path string) bool {
	return c.isExcludedPath(path) || c.excludeExts[strings.ToLower(filepath.Ext(path))]
}

// parseHunkStart는 "@@ -12,3 +34,5 @@" 형태에서 새 파일 기준 시작 줄 번호(34)를 뽑는다.
func parseHunkStart(line string) int {
	plus := strings.Index(line, "+")
	if plus < 0 {
		return 1
	}
	rest := line[plus+1:]

	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return 1
	}

	n, err := strconv.Atoi(rest[:end])
	if err != nil || n < 1 {
		return 1
	}
	return n
}

func ensureGitRepo(root string) error {
	out, err := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("%s 은(는) git 레포가 아닙니다", root)
		}
		return fmt.Errorf("git 실행 실패 (git이 설치되어 있는지 확인하세요): %w", err)
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("%s 은(는) git 워킹트리가 아닙니다", root)
	}
	return nil
}

// RepoRoot는 경로가 속한 git 워킹트리의 최상위 폴더를 절대경로로 돌려준다.
// git 저장소가 아니거나 git이 설치되어 있지 않으면 빈 문자열을 돌려준다.
func RepoRoot(path string) string {
	out, err := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}

	root := strings.TrimSpace(string(out))
	if root == "" {
		return ""
	}
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return root
}

// IsRepoRoot는 지정한 경로가 git 저장소의 최상위 폴더인지 확인한다.
//
// "이 폴더가 저장소인가"를 rev-parse --is-inside-work-tree 로만 판단하면 안 된다.
// 그 질문은 상위 폴더까지 거슬러 올라가며 답하기 때문에, 홈 디렉토리가 저장소인
// 환경에서는 아무 폴더나 true가 나온다. 그 상태로 히스토리 스캔을 켜면 사용자가
// 고른 폴더와 아무 상관 없는 저장소의 커밋을 훑게 된다.
func IsRepoRoot(path string) bool {
	root := RepoRoot(path)
	if root == "" {
		return false
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return sameDir(abs, root)
}

// sameDir는 두 경로가 같은 폴더를 가리키는지 확인한다. Windows는 대소문자와 경로
// 구분자가 섞여 나올 수 있어 문자열 비교만으로는 부족하므로 실제 파일 정보로 확인한다.
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}

	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// HasCommits는 저장소에 커밋이 하나라도 있는지 확인한다.
// git init 직후처럼 커밋이 없으면 git log 는 실패하므로 히스토리 스캔 전에 걸러야 한다.
func HasCommits(root string) bool {
	return exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD").Run() == nil
}

// unquotePath는 git이 따옴표로 감싼 경로를 원래 문자열로 되돌린다.
//
// git은 경로에 특수문자(따옴표, 역슬래시, 제어문자)가 있거나 core.quotepath가
// 켜져 있을 때 경로를 C 문자열처럼 감싸 내보낸다:
//
//	+++ "b/docs/\354\232\251\354\226\264\354\247\221.md"
//
// 이 형태를 풀지 않으면 경로가 워킹트리 쪽과 달라져, 같은 시크릿이 서로 다른
// 두 건으로 보고된다. 8진수 이스케이프는 UTF-8 바이트 단위이므로 바이트로
// 모아서 마지막에 문자열로 만든다.
//
// 감싸이지 않은 경로는 그대로 돌려준다.
func unquotePath(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	body := s[1 : len(s)-1]

	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' || i+1 >= len(body) {
			out = append(out, body[i])
			continue
		}

		i++
		switch c := body[i]; c {
		case 'a':
			out = append(out, '\a')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, '\v')
		case '\\', '"':
			out = append(out, c)
		default:
			// 8진수 3자리 (\354 등). 형식이 어긋나면 원문을 살려 둔다 —
			// 경로를 조용히 망가뜨리는 것보다 낫다.
			if i+2 < len(body) && isOctal(body[i]) && isOctal(body[i+1]) && isOctal(body[i+2]) {
				v := (body[i]-'0')<<6 | (body[i+1]-'0')<<3 | (body[i+2] - '0')
				out = append(out, v)
				i += 2
				continue
			}
			out = append(out, '\\', c)
		}
	}
	return string(out)
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }
