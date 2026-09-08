package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whiteclover0542/secrethound/internal/finding"
)

func f(path, ruleID, secret string, line int) finding.Finding {
	return finding.Finding{Path: path, RuleID: ruleID, Secret: secret, Line: line}
}

// 라인 번호만 바뀌어도 지문은 그대로여야 baseline이 "새로 생긴 것"으로 오판하지 않는다.
func TestFingerprintIgnoresLineNumber(t *testing.T) {
	a := f("app.js", "github-pat", "ghp_same", 10)
	b := f("app.js", "github-pat", "ghp_same", 200)

	if Fingerprint(a) != Fingerprint(b) {
		t.Error("같은 파일·룰·값인데 줄 번호가 다르다고 지문이 달라짐")
	}
}

// 같은 키가 다른 파일에 있으면 각각 추적해야 전부 지웠는지 확인할 수 있다.
func TestFingerprintDiffersByPath(t *testing.T) {
	a := f("a.js", "github-pat", "ghp_same", 1)
	b := f("b.js", "github-pat", "ghp_same", 1)

	if Fingerprint(a) == Fingerprint(b) {
		t.Error("파일이 다른데 지문이 같음 — 한쪽만 지워도 baseline에서 둘 다 사라진다")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	findings := []finding.Finding{
		f("a.js", "github-pat", "ghp_1", 1),
		f("b.js", "aws-access-key-id", "AKIA1", 5),
	}

	if err := Save(path, findings); err != nil {
		t.Fatalf("Save 실패: %v", err)
	}

	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load 실패: %v", err)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("Entries = %d, 기대값 2", len(b.Entries))
	}

	// 저장된 파일에 원본 시크릿 값이 그대로 남으면 baseline 자체가 유출 경로가 된다.
	for _, e := range b.Entries {
		if e.Hash == "ghp_1" || e.Hash == "AKIA1" {
			t.Errorf("baseline에 원본 시크릿 값이 그대로 저장됨: %+v", e)
		}
	}
}

func TestLoadRejectsWrongVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	data := []byte(`{"version": 999, "entries": []}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("지원하지 않는 버전인데 에러 없이 로드됨")
	}
}

func TestSplitSeparatesKnownFromNew(t *testing.T) {
	known := f("a.js", "github-pat", "ghp_known", 1)
	fresh := f("a.js", "github-pat", "ghp_new", 2)

	b := From([]finding.Finding{known})

	newOnes, knownCount := Split(b, []finding.Finding{known, fresh})
	if knownCount != 1 {
		t.Errorf("known = %d, 기대값 1", knownCount)
	}
	if len(newOnes) != 1 || newOnes[0].Secret != "ghp_new" {
		t.Errorf("new = %+v, ghp_new 하나만 남아야 한다", newOnes)
	}
}

func TestFromDeduplicates(t *testing.T) {
	dup := f("a.js", "github-pat", "ghp_same", 1)
	b := From([]finding.Finding{dup, dup, dup})
	if len(b.Entries) != 1 {
		t.Errorf("중복 제거 안 됨: %d건", len(b.Entries))
	}
}
