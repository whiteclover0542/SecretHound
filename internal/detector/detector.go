package detector

import (
	"bytes"
	"strings"

	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

const initialConfidence = 100

type Detector struct {
	rules []compiledRule
}

type compiledRule struct {
	cfg      *config.Rule
	keywords []string // 라인마다 소문자 변환하지 않도록 미리 소문자화해 둔다
}

func New(rules []config.Rule) *Detector {
	d := &Detector{rules: make([]compiledRule, 0, len(rules))}
	for i := range rules {
		cr := compiledRule{cfg: &rules[i]}
		for _, k := range rules[i].Keywords {
			cr.keywords = append(cr.keywords, strings.ToLower(k))
		}
		d.rules = append(d.rules, cr)
	}
	return d
}

// Scan은 파일 내용을 라인 단위로 훑으며 룰에 매칭되는 시크릿을 찾는다.
func (d *Detector) Scan(path, commit string, content []byte) []finding.Finding {
	var findings []finding.Finding

	for i, raw := range bytes.Split(content, []byte("\n")) {
		line := strings.TrimRight(string(raw), "\r")
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)

		for _, r := range d.rules {
			// 키워드 프리필터: 정규식 실행 자체를 줄여 스캔 속도를 확보한다.
			if !r.hasKeyword(lower) {
				continue
			}

			for _, m := range r.cfg.Pattern.FindAllStringSubmatchIndex(line, -1) {
				secret, start := extractGroup(line, m, r.cfg.SecretGroup)
				if secret == "" {
					continue
				}

				entropy := Shannon(secret)
				if r.cfg.Entropy > 0 && entropy < r.cfg.Entropy {
					continue
				}

				findings = append(findings, finding.Finding{
					RuleID:      r.cfg.ID,
					Description: r.cfg.Description,
					Severity:    r.cfg.Severity,
					Path:        path,
					Commit:      commit,
					Line:        i + 1,
					Column:      start + 1,
					Entropy:     entropy,
					Confidence:  initialConfidence,
					Tags:        r.cfg.Tags,
					Secret:      secret,
					Masked:      Mask(secret),
				})
			}
		}
	}

	return findings
}

func (r compiledRule) hasKeyword(lowerLine string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	for _, k := range r.keywords {
		if strings.Contains(lowerLine, k) {
			return true
		}
	}
	return false
}

// extractGroup은 지정한 캡처 그룹의 문자열과 시작 위치를 돌려준다.
// 그룹이 매칭에 참여하지 않았으면 인덱스가 -1이므로 걸러낸다.
func extractGroup(line string, match []int, group int) (string, int) {
	lo, hi := 2*group, 2*group+1
	if hi >= len(match) || match[lo] < 0 {
		return "", 0
	}
	return line[match[lo]:match[hi]], match[lo]
}

// Mask는 어떤 키인지 식별은 가능하되 그대로 재사용할 수는 없도록 값을 가린다.
func Mask(secret string) string {
	const head, tail = 6, 4
	if len(secret) <= head+tail {
		return strings.Repeat("*", len(secret))
	}
	return secret[:head] + strings.Repeat("*", 6) + secret[len(secret)-tail:]
}
