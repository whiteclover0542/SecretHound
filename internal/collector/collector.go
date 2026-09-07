package collector

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/whiteclover0542/secrethound/internal/config"
)

const (
	defaultMaxFileSize = 10 << 20 // 10MB
	binarySniffLen     = 8000     // git과 동일하게 앞부분만 보고 바이너리 판별
)

// Source는 탐지 엔진에 전달되는 스캔 단위다.
// Commit이 비어 있으면 워킹트리의 현재 파일, 값이 있으면 해당 커밋의 변경 내용을 의미한다.
type Source struct {
	Path    string
	Commit  string
	Content []byte
}

type Stats struct {
	Scanned int
	Skipped int
}

type Collector struct {
	filter      *config.Filter
	excludeExts map[string]bool
	maxFileSize int64
}

func New(filter *config.Filter) *Collector {
	exts := make(map[string]bool, len(filter.ExcludeExtensions))
	for _, e := range filter.ExcludeExtensions {
		exts[strings.ToLower(e)] = true
	}
	return &Collector{
		filter:      filter,
		excludeExts: exts,
		maxFileSize: defaultMaxFileSize,
	}
}

// WalkTree는 root 이하의 텍스트 파일을 순회하며 fn을 호출한다.
// 파일을 통째로 메모리에 올리지 않도록 파일 단위로 스트리밍한다.
func (c *Collector) WalkTree(root string, fn func(Source) error) (Stats, error) {
	var stats Stats

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if rel != "." && c.isExcludedPath(rel+"/") {
				return fs.SkipDir
			}
			return nil
		}

		// 심볼릭 링크를 따라가면 레포 밖 파일까지 읽게 되므로 건너뛴다.
		if d.Type()&fs.ModeSymlink != 0 {
			stats.Skipped++
			return nil
		}

		if c.isExcludedPath(rel) || c.excludeExts[strings.ToLower(filepath.Ext(rel))] {
			stats.Skipped++
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Size() == 0 || info.Size() > c.maxFileSize {
			stats.Skipped++
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("파일 읽기 실패 %s: %w", rel, readErr)
		}
		if isBinary(content) {
			stats.Skipped++
			return nil
		}

		stats.Scanned++
		return fn(Source{Path: rel, Content: content})
	})

	return stats, err
}

func (c *Collector) isExcludedPath(rel string) bool {
	for _, p := range c.filter.ExcludePathPatterns {
		if p.MatchString(rel) {
			return true
		}
	}
	return false
}

// NUL 바이트가 있으면 바이너리로 간주한다 (git의 휴리스틱과 동일).
func isBinary(content []byte) bool {
	if len(content) > binarySniffLen {
		content = content[:binarySniffLen]
	}
	return bytes.IndexByte(content, 0) >= 0
}
