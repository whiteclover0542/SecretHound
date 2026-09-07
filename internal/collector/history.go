package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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

	args := []string{
		"-C", root, "log",
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
			if path == "/dev/null" {
				skip = true
				continue
			}
			current.Path = strings.TrimPrefix(path, "b/")
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
