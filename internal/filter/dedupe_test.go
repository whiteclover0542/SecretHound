package filter

import (
	"testing"

	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

func at(rule string, sev config.Severity, line int, secret string) finding.Finding {
	return finding.Finding{RuleID: rule, Severity: sev, Path: "main.tf", Line: line, Secret: secret}
}

// 구체적인 룰과 범용 룰이 같은 값을 동시에 잡으면 심각도가 높은 쪽만 남아야 한다.
func TestDedupeKeepsMostSevere(t *testing.T) {
	const secret = "kR7vQ2mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pX"

	got := Dedupe([]finding.Finding{
		at("aws-secret-access-key-bare", config.SeverityCritical, 4, secret),
		at("generic-api-key", config.SeverityMedium, 4, secret),
	})

	if len(got) != 1 {
		t.Fatalf("중복이 제거되지 않음: %d건", len(got))
	}
	if got[0].RuleID != "aws-secret-access-key-bare" {
		t.Errorf("남은 룰 = %s, 기대값 aws-secret-access-key-bare", got[0].RuleID)
	}
}

// 룰셋 순서상 먼저 정의된(더 구체적인) 룰이 남아야 한다.
func TestDedupeTieKeepsFirst(t *testing.T) {
	got := Dedupe([]finding.Finding{
		at("specific-rule", config.SeverityHigh, 1, "abc"),
		at("other-rule", config.SeverityHigh, 1, "abc"),
	})

	if len(got) != 1 || got[0].RuleID != "specific-rule" {
		t.Errorf("동점 시 먼저 나온 룰이 남지 않음: %+v", got)
	}
}

func TestDedupeKeepsDistinctLocations(t *testing.T) {
	got := Dedupe([]finding.Finding{
		at("rule", config.SeverityHigh, 1, "abc"),
		at("rule", config.SeverityHigh, 2, "abc"),
		at("rule", config.SeverityHigh, 1, "xyz"),
	})

	if len(got) != 3 {
		t.Errorf("서로 다른 위치/값이 병합됨: %d건", len(got))
	}
}

// 워킹트리와 히스토리의 결과는 커밋이 다르므로 각각 남아야 한다.
func TestDedupeSeparatesCommits(t *testing.T) {
	worktree := at("rule", config.SeverityHigh, 1, "abc")
	historical := worktree
	historical.Commit = "abc1234"

	if got := Dedupe([]finding.Finding{worktree, historical}); len(got) != 2 {
		t.Errorf("워킹트리와 히스토리 결과가 병합됨: %d건", len(got))
	}
}
