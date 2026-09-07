package filter

import (
	"testing"

	"github.com/whiteclover0542/secrethound/internal/finding"
)

func occurrence(path, secret, commit, date string, line int) finding.Finding {
	return finding.Finding{
		RuleID: "generic-api-key",
		Path:   path,
		Secret: secret,
		Commit: commit,
		Date:   date,
		Line:   line,
	}
}

// 히스토리 스캔에서 같은 값이 여러 커밋에 걸쳐 나오면 최초 유입 하나로 묶여야 한다.
func TestGroupBySecretCollapsesHistory(t *testing.T) {
	got := GroupBySecret([]finding.Finding{
		occurrence("docs/config.rst", "192b9b", "aaa1111", "2023-05-01T00:00:00Z", 41),
		occurrence("docs/config.rst", "192b9b", "bbb2222", "2021-01-01T00:00:00Z", 471),
		occurrence("docs/config.rst", "192b9b", "ccc3333", "2022-03-01T00:00:00Z", 513),
	})

	if len(got) != 1 {
		t.Fatalf("묶이지 않음: %d건", len(got))
	}
	if got[0].Commit != "bbb2222" {
		t.Errorf("대표 커밋 = %s, 기대값 bbb2222 (가장 이른 유입)", got[0].Commit)
	}
	if got[0].Line != 471 {
		t.Errorf("Line = %d, 최초 유입 시점의 줄 번호여야 한다", got[0].Line)
	}
	if got[0].Occurrences != 3 {
		t.Errorf("Occurrences = %d, 기대값 3", got[0].Occurrences)
	}
	if got[0].InWorktree {
		t.Error("워킹트리 결과가 없는데 InWorktree 가 true")
	}
}

// 같은 키가 여러 파일에 박혀 있으면 전부 지워야 하므로 각각 보고해야 한다.
func TestGroupBySecretKeepsDistinctFiles(t *testing.T) {
	got := GroupBySecret([]finding.Finding{
		occurrence("config/services.env", "SK9f86", "", "", 3),
		occurrence("src/integrations.js", "SK9f86", "", "", 4),
	})

	if len(got) != 2 {
		t.Errorf("다른 파일의 같은 값이 병합됨: %d건", len(got))
	}
}

// 과거에 유입됐고 지금도 남아있는 경우, 위치는 최초 유입을 가리키되
// 현재도 존재한다는 사실이 남아야 한다.
func TestGroupBySecretMarksWorktreePresence(t *testing.T) {
	got := GroupBySecret([]finding.Finding{
		occurrence("src/current.js", "sk_live_x", "", "", 1),
		occurrence("src/current.js", "sk_live_x", "abc1234", "2024-02-01T00:00:00Z", 1),
	})

	if len(got) != 1 {
		t.Fatalf("묶이지 않음: %d건", len(got))
	}
	if got[0].Commit != "abc1234" {
		t.Errorf("대표 = 워킹트리 결과, 최초 유입 커밋이어야 한다")
	}
	if !got[0].InWorktree {
		t.Error("현재 파일에도 있는데 InWorktree 가 false")
	}
	if got[0].Occurrences != 2 {
		t.Errorf("Occurrences = %d, 기대값 2", got[0].Occurrences)
	}
}

func TestGroupBySecretSingleFinding(t *testing.T) {
	got := GroupBySecret([]finding.Finding{
		occurrence("a.go", "secret", "", "", 1),
	})

	if len(got) != 1 || got[0].Occurrences != 1 || !got[0].InWorktree {
		t.Errorf("단일 결과 처리가 잘못됨: %+v", got)
	}
}
