package filter

import (
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

// Dedupe는 같은 위치의 같은 값이 여러 룰에 걸린 경우 하나만 남긴다.
//
// 구체적인 룰(aws-secret-access-key)과 범용 룰(generic-api-key)이 같은 줄을 동시에 잡으면
// 사용자에게 같은 시크릿이 두 번 보고되고, 그중 낮은 심각도가 섞여 우선순위 판단을 방해한다.
// 심각도가 높은 쪽을 남기고, 같으면 먼저 나온 쪽(룰셋에 먼저 정의된 더 구체적인 룰)을 남긴다.
func Dedupe(findings []finding.Finding) []finding.Finding {
	type key struct {
		path   string
		commit string
		line   int
		secret string
	}

	seen := make(map[key]int, len(findings))
	out := make([]finding.Finding, 0, len(findings))

	for _, f := range findings {
		k := key{f.Path, f.Commit, f.Line, f.Secret}

		idx, ok := seen[k]
		if !ok {
			seen[k] = len(out)
			out = append(out, f)
			continue
		}
		if config.SeverityRank(f.Severity) < config.SeverityRank(out[idx].Severity) {
			out[idx] = f
		}
	}

	return out
}
