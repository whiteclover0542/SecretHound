package filter

import (
	"testing"

	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

func newFilter(t *testing.T) *Filter {
	t.Helper()
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		t.Fatalf("기본 룰셋 로드 실패: %v", err)
	}
	f, err := New(&rs.Filter)
	if err != nil {
		t.Fatalf("필터 생성 실패: %v", err)
	}
	return f
}

func sample(path, secret string) finding.Finding {
	return finding.Finding{
		RuleID:     "aws-access-key-id",
		Path:       path,
		Secret:     secret,
		Confidence: 100,
	}
}

func TestApplyFiltersPlaceholders(t *testing.T) {
	cases := []struct {
		name string
		in   finding.Finding
		keep bool
	}{
		{"실제 시크릿", sample("src/config.go", "AKIA2E0A8F3B244C9986"), true},
		{"플레이스홀더 값", sample("src/config.go", "AKIAXXXXXXXXXXXXXXXX"), false},
		{"문자 반복", sample("src/config.go", "AKIA0000000000000000"), false},
		{"테스트 디렉토리", sample("test/fixtures.go", "AKIA2E0A8F3B244C9986"), true},
		{"테스트 파일 + 플레이스홀더", sample("config_test.go", "AKIAEXAMPLE123456789"), false},
		{".env 예시 파일", sample(".env.example", "AKIA2E0A8F3B244C9986"), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, _ := newFilter(t).Apply([]finding.Finding{tc.in})
			if got := len(kept) == 1; got != tc.keep {
				t.Errorf("유지 여부 = %v, 기대값 %v (신뢰도 계산 확인 필요)", got, tc.keep)
			}
		})
	}
}

func TestApplyAllowlist(t *testing.T) {
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		t.Fatal(err)
	}
	rs.Filter.Allowlist.RuleIDs = []string{"aws-access-key-id"}

	f, err := New(&rs.Filter)
	if err != nil {
		t.Fatal(err)
	}

	kept, stats := f.Apply([]finding.Finding{sample("src/config.go", "AKIA2E0A8F3B244C9986")})
	if len(kept) != 0 {
		t.Errorf("allowlist에 등록된 룰이 걸러지지 않음: %+v", kept)
	}
	if stats.Allowlist != 1 {
		t.Errorf("Allowlist 카운트 = %d, 기대값 1", stats.Allowlist)
	}
}

func TestHasRepeatedRun(t *testing.T) {
	if !hasRepeatedRun("abcXXXXXXXXdef", 8) {
		t.Error("8회 연속 반복을 탐지하지 못함")
	}
	if hasRepeatedRun("abcXXXXdef", 8) {
		t.Error("4회 반복을 8회로 오판함")
	}
}
