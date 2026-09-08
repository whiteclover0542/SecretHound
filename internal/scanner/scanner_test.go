package scanner

import (
	"os"
	"path/filepath"
	"testing"

	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/baseline"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/validator"
)

// 검증은 찾아낸 자격증명을 외부로 내보내는 동작이라 켜지 않으면 절대 돌면 안 된다.
// 기본값이 조용히 뒤집히는 것을 막는 안전장치다.
func TestValidationIsOffByDefault(t *testing.T) {
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Run(t.Context(), rs, Options{Target: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	if result.Validated {
		t.Error("Validate.Enabled가 false인데 검증이 돌았다")
	}
	if result.Validation != (validator.Stats{}) {
		t.Errorf("검증하지 않았는데 집계가 채워짐: %+v", result.Validation)
	}
	for _, f := range result.Findings {
		if f.Validation != nil {
			t.Errorf("검증하지 않았는데 결과가 붙음: %s", f.Path)
		}
	}
}

// baseline에 이미 있는 시크릿은 결과뿐 아니라 검증 대상에서도 빠져야 한다.
// 그러지 않으면 이미 알고 있는 값까지 매번 발급처에 물어보게 되어
// 네트워크 호출과 레이트리밋을 아무 의미 없이 소모한다.
func TestBaselineSuppressesBeforeValidation(t *testing.T) {
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	content := `const token = "ghp_9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXk";`
	if err := os.WriteFile(filepath.Join(dir, "config.js"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := Run(t.Context(), rs, Options{Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != 1 {
		t.Fatalf("사전 조건 실패: 탐지 %d건, 기대값 1", len(first.Findings))
	}

	bl := baseline.From(first.Findings)

	second, err := Run(t.Context(), rs, Options{
		Target:   dir,
		Baseline: bl,
		Validate: ValidateOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(second.Findings) != 0 {
		t.Errorf("baseline에 있는 시크릿이 결과에 남음: %+v", second.Findings)
	}
	if second.BaselineKnown != 1 {
		t.Errorf("BaselineKnown = %d, 기대값 1", second.BaselineKnown)
	}
	if second.Validation.Checked != 0 {
		t.Errorf("baseline으로 제외된 값인데 검증을 시도함: %+v", second.Validation)
	}
}
