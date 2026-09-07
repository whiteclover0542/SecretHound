package detector

import "math"

// Shannon 엔트로피(비트/문자)를 계산한다.
// 값이 높을수록 무작위에 가까워 시크릿일 가능성이 크다.
// 시크릿은 ASCII로만 구성되므로 룬이 아닌 바이트 단위로 집계한다.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}

	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}

	length := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
