package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

// 정규식 매칭을 워커 풀에 분산시키면 파일마다 완료 순서가 뒤섞인다.
// Dedupe/GroupBySecret이 그 순서에 의존해 결과가 실행마다 달라지면 안 되므로,
// 여러 파일에 서로 다른 시크릿을 흩어놓고 여러 번 스캔해 항상 같은 결과가
// 나오는지 확인한다.
func TestParallelScanIsDeterministic(t *testing.T) {
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	secrets := []string{
		`const t = "ghp_9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXk";`,
		`AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986`,
		`const s = "sk_live_51NxK2mQ7vRp8ZtY3wB6cH0j";`,
	}
	for i := 0; i < 20; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file%02d.txt", i))
		content := secrets[i%len(secrets)]
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var want []string
	for run := 0; run < 5; run++ {
		result, err := Run(t.Context(), rs, Options{Target: dir})
		if err != nil {
			t.Fatal(err)
		}

		got := fingerprints(result.Findings)
		if run == 0 {
			want = got
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("실행 %d: 탐지 %d건, 첫 실행은 %d건", run, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("실행 %d: 결과가 이전 실행과 다름\n want %v\n got  %v", run, want, got)
				break
			}
		}
	}
}

func fingerprints(findings []finding.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = fmt.Sprintf("%s:%d:%s:%s", f.Path, f.Line, f.RuleID, f.Secret)
	}
	sort.Strings(out)
	return out
}
