package filter

import "github.com/whiteclover0542/secrethound/internal/finding"

// GroupBySecret은 같은 파일에 있는 같은 값을 하나로 묶는다.
//
// 히스토리를 스캔하면 하나의 시크릿이 그것을 건드린 커밋 수만큼 보고된다.
// 실제로 오래된 레포를 스캔해보면 같은 값이 수십 줄로 늘어나 리포트를 읽을 수 없게 된다.
//
// 묶은 결과는 **최초 유입 시점**을 가리킨다. 유출 대응에서 정작 필요한 정보가
// "언제 처음 들어왔는가"이기 때문이다.
//
// 파일이 다르면 묶지 않는다. 같은 키가 여러 파일에 하드코딩된 경우
// 전부 찾아 지워야 하므로 각각 보고해야 한다.
func GroupBySecret(findings []finding.Finding) []finding.Finding {
	type key struct {
		path   string
		secret string
	}

	index := make(map[key]int, len(findings))
	out := make([]finding.Finding, 0, len(findings))

	for _, f := range findings {
		k := key{f.Path, f.Secret}

		i, ok := index[k]
		if !ok {
			f.Occurrences = 1
			f.InWorktree = f.Commit == ""
			index[k] = len(out)
			out = append(out, f)
			continue
		}

		cur := &out[i]
		cur.Occurrences++
		if f.Commit == "" {
			cur.InWorktree = true
		}

		if isEarlier(f, *cur) {
			occurrences, inWorktree := cur.Occurrences, cur.InWorktree
			*cur = f
			cur.Occurrences, cur.InWorktree = occurrences, inWorktree
		}
	}

	return out
}

// isEarlier는 a가 b보다 앞선 유입인지 판단한다.
// 날짜는 ISO 8601 이라 문자열 비교로 시간 순서가 맞는다.
// 워킹트리 결과에는 날짜가 없으므로, 최초 유입 정보로는 히스토리 결과를 우선한다.
func isEarlier(a, b finding.Finding) bool {
	if a.Date == "" {
		return false
	}
	if b.Date == "" {
		return true
	}
	return a.Date < b.Date
}
