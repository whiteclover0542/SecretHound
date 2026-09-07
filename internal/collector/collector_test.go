package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiteclover0542/secrethound/internal/config"
)

func newTestCollector(t *testing.T) *Collector {
	t.Helper()

	rs, err := config.Parse([]byte(`
version: 1
rules:
  - id: dummy
    description: 테스트용
    severity: low
    regex: 'never-match-xyz'
    secret_group: 0
filter:
  exclude_paths:
    - '(^|/)node_modules/'
  exclude_extensions:
    - .png
`))
	if err != nil {
		t.Fatalf("룰셋 파싱 실패: %v", err)
	}
	return New(&rs.Filter)
}

func TestWalkTree(t *testing.T) {
	root := t.TempDir()

	files := map[string][]byte{
		"main.go":             []byte("package main"),
		"node_modules/lib.js": []byte("var a = 1"),
		"logo.png":            []byte("fake png"),
		"binary.dat":          {0x01, 0x00, 0x02},
		"empty.txt":           {},
		"src/config.yaml":     []byte("key: value"),
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var collected []string
	stats, err := newTestCollector(t).WalkTree(root, func(s Source) error {
		collected = append(collected, s.Path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkTree 실패: %v", err)
	}

	want := map[string]bool{"main.go": true, "src/config.yaml": true}
	if len(collected) != len(want) {
		t.Fatalf("수집된 파일 = %v, 기대값 = %v", collected, want)
	}
	for _, path := range collected {
		if !want[path] {
			t.Errorf("수집되면 안 되는 파일이 포함됨: %s", path)
		}
	}
	if stats.Scanned != 2 {
		t.Errorf("Scanned = %d, 기대값 2", stats.Scanned)
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("plain text")) {
		t.Error("텍스트를 바이너리로 판정함")
	}
	if !isBinary([]byte{'a', 0x00, 'b'}) {
		t.Error("NUL 포함 데이터를 바이너리로 판정하지 못함")
	}
}
