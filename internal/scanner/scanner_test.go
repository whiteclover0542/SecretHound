package scanner

import (
	"testing"

	secrethound "github.com/whiteclover0542/secrethound"
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
