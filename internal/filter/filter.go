package filter

import (
	"fmt"
	"regexp"

	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

const (
	maxConfidence = 100
	// 같은 문자가 이 횟수 이상 연속되면 마스킹된 값으로 본다.
	repeatedCharRun = 8
)

// Filter는 탐지 결과의 신뢰도를 조정해 오탐을 걸러낸다.
// 명백한 제외 대상(allowlist)은 즉시 버리고, 나머지는 감점 후 임계값으로 판단한다.
type Filter struct {
	cfg            *config.Filter
	allowedRules   map[string]bool
	allowedSecrets map[string]bool
	allowedPaths   []*regexp.Regexp
}

type Stats struct {
	Kept      int
	Filtered  int
	Allowlist int
}

func New(cfg *config.Filter) (*Filter, error) {
	f := &Filter{
		cfg:            cfg,
		allowedRules:   toSet(cfg.Allowlist.RuleIDs),
		allowedSecrets: toSet(cfg.Allowlist.Secrets),
	}

	for _, expr := range cfg.Allowlist.Paths {
		p, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("allowlist path %q: 정규식 컴파일 실패: %w", expr, err)
		}
		f.allowedPaths = append(f.allowedPaths, p)
	}

	return f, nil
}

func (f *Filter) Apply(findings []finding.Finding) ([]finding.Finding, Stats) {
	var stats Stats
	kept := make([]finding.Finding, 0, len(findings))

	for _, found := range findings {
		if f.isAllowlisted(found) {
			stats.Allowlist++
			continue
		}

		found.Confidence = f.score(found)
		if found.Confidence < f.cfg.MinConfidence {
			stats.Filtered++
			continue
		}

		stats.Kept++
		kept = append(kept, found)
	}

	return kept, stats
}

func (f *Filter) isAllowlisted(found finding.Finding) bool {
	if f.allowedRules[found.RuleID] || f.allowedSecrets[found.Secret] {
		return true
	}
	for _, p := range f.allowedPaths {
		if p.MatchString(found.Path) {
			return true
		}
	}
	return false
}

func (f *Filter) score(found finding.Finding) int {
	score := found.Confidence

	for _, pen := range f.cfg.Penalties {
		subject := found.Path
		if pen.Target == config.TargetValue {
			subject = found.Secret
		}

		if !matches(pen, subject) {
			continue
		}
		score += pen.Score
	}

	if score < 0 {
		return 0
	}
	if score > maxConfidence {
		return maxConfidence
	}
	return score
}

func matches(pen config.Penalty, subject string) bool {
	if pen.Builtin == config.BuiltinRepeatedChars {
		return hasRepeatedRun(subject, repeatedCharRun)
	}
	return pen.Compiled != nil && pen.Compiled.MatchString(subject)
}

// hasRepeatedRun은 같은 문자가 n회 이상 연속되는지 검사한다.
// RE2는 백레퍼런스를 지원하지 않아 정규식으로 표현할 수 없으므로 직접 구현한다.
func hasRepeatedRun(s string, n int) bool {
	if len(s) < n {
		return false
	}
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] != s[i-1] {
			run = 1
			continue
		}
		run++
		if run >= n {
			return true
		}
	}
	return false
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, it := range items {
		set[it] = true
	}
	return set
}
