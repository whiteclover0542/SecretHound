package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
}

// SeverityRank는 심각도 순위를 돌려준다. 값이 작을수록 심각하다.
// 알 수 없는 값은 가장 낮은 순위로 취급한다.
func SeverityRank(s Severity) int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return len(severityRank)
}

type Ruleset struct {
	Version int     `yaml:"version"`
	Rules   []Rule  `yaml:"rules"`
	Entropy Entropy `yaml:"entropy"`
	Filter  Filter  `yaml:"filter"`
}

type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Severity    Severity `yaml:"severity"`
	Keywords    []string `yaml:"keywords"`
	Regex       string   `yaml:"regex"`
	SecretGroup int      `yaml:"secret_group"`
	Entropy     float64  `yaml:"entropy"`
	Tags        []string `yaml:"tags"`
	// Remediation은 이 종류의 키를 발급처에서 폐기(revoke)하는 절차 안내다.
	// 탐지만으로 끝나지 않고 대응까지 이어지도록 Finding에 그대로 실린다.
	Remediation string `yaml:"remediation"`

	Pattern *regexp.Regexp `yaml:"-"`
}

type Entropy struct {
	Enabled    bool               `yaml:"enabled"`
	MinLength  int                `yaml:"min_length"`
	MaxLength  int                `yaml:"max_length"`
	Thresholds map[string]float64 `yaml:"thresholds"`
	Severity   Severity           `yaml:"severity"`
}

type Filter struct {
	MinConfidence     int       `yaml:"min_confidence"`
	ExcludePaths      []string  `yaml:"exclude_paths"`
	ExcludeExtensions []string  `yaml:"exclude_extensions"`
	Penalties         []Penalty `yaml:"penalties"`
	Allowlist         Allowlist `yaml:"allowlist"`

	ExcludePathPatterns []*regexp.Regexp `yaml:"-"`
}

// 감점 규칙이 무엇을 검사 대상으로 삼는지 구분한다.
const (
	TargetPath  = "path"
	TargetValue = "value"
)

// 정규식(RE2)으로 표현할 수 없어 코드로 구현하는 규칙의 식별자.
const BuiltinRepeatedChars = "repeated-chars"

type Penalty struct {
	ID      string `yaml:"id"`
	Target  string `yaml:"target"`  // path | value (기본 path)
	Pattern string `yaml:"pattern"` // Builtin과 택일
	Builtin string `yaml:"builtin"` // Pattern과 택일
	Score   int    `yaml:"score"`
	Reason  string `yaml:"reason"`

	Compiled *regexp.Regexp `yaml:"-"`
}

type Allowlist struct {
	RuleIDs []string `yaml:"rule_ids"`
	Paths   []string `yaml:"paths"`
	Secrets []string `yaml:"secrets"`
}

func Load(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("룰셋 파일 읽기 실패: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Ruleset, error) {
	var rs Ruleset
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("룰셋 파싱 실패: %w", err)
	}
	if err := rs.compile(); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (rs *Ruleset) compile() error {
	if len(rs.Rules) == 0 {
		return fmt.Errorf("룰셋에 규칙이 하나도 없습니다")
	}

	seen := make(map[string]bool, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("rules[%d]: id가 비어 있습니다", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("rules[%d]: 중복된 id %q", i, r.ID)
		}
		seen[r.ID] = true

		p, err := regexp.Compile(r.Regex)
		if err != nil {
			return fmt.Errorf("rule %q: 정규식 컴파일 실패: %w", r.ID, err)
		}
		if r.SecretGroup > p.NumSubexp() {
			return fmt.Errorf("rule %q: secret_group %d 이 캡처 그룹 수(%d)를 초과합니다",
				r.ID, r.SecretGroup, p.NumSubexp())
		}
		r.Pattern = p
	}

	for i := range rs.Filter.Penalties {
		pen := &rs.Filter.Penalties[i]

		switch pen.Target {
		case "":
			pen.Target = TargetPath
		case TargetPath, TargetValue:
		default:
			return fmt.Errorf("penalty %q: 알 수 없는 target %q", pen.ID, pen.Target)
		}

		if (pen.Pattern == "") == (pen.Builtin == "") {
			return fmt.Errorf("penalty %q: pattern과 builtin 중 정확히 하나만 지정해야 합니다", pen.ID)
		}

		if pen.Builtin != "" {
			if pen.Builtin != BuiltinRepeatedChars {
				return fmt.Errorf("penalty %q: 지원하지 않는 builtin %q", pen.ID, pen.Builtin)
			}
			continue
		}

		p, err := regexp.Compile(pen.Pattern)
		if err != nil {
			return fmt.Errorf("penalty %q: 정규식 컴파일 실패: %w", pen.ID, err)
		}
		pen.Compiled = p
	}

	for _, expr := range rs.Filter.ExcludePaths {
		p, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("exclude_paths %q: 정규식 컴파일 실패: %w", expr, err)
		}
		rs.Filter.ExcludePathPatterns = append(rs.Filter.ExcludePathPatterns, p)
	}

	return nil
}
