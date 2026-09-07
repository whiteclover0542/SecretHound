package finding

import (
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/validator"
)

// Finding은 Detection Engine → FP Filter → Reporter로 전달되는 탐지 결과 단위다.
type Finding struct {
	RuleID      string          `json:"rule_id"`
	Description string          `json:"description"`
	Severity    config.Severity `json:"severity"`
	Path        string          `json:"path"`
	Commit      string          `json:"commit,omitempty"`
	Author      string          `json:"author,omitempty"`
	Date        string          `json:"date,omitempty"`
	Line        int             `json:"line"`
	Column      int             `json:"column"`
	Entropy     float64         `json:"entropy"`
	Confidence  int             `json:"confidence"`
	Tags        []string        `json:"tags,omitempty"`

	// 같은 값이 여러 커밋·줄에 걸쳐 나타나면 하나로 묶고, 위치는 최초 유입 시점을 가리킨다.
	// Occurrences 는 묶인 개수, InWorktree 는 현재 파일에도 남아있는지를 뜻한다.
	Occurrences int  `json:"occurrences"`
	InWorktree  bool `json:"in_worktree"`

	// Validation은 --validate 로 발급처에 살아있는지 확인한 결과다.
	// 검증하지 않았으면 nil이며, "검증 안 함"과 "검증했으나 판단 불가"는 다른 상태다.
	Validation *validator.Result `json:"validation,omitempty"`

	// 리포트 파일이 또 다른 유출 경로가 되지 않도록 원본 값은 직렬화하지 않는다.
	// 노출이 필요한 경우 Reporter에서 명시적 옵션으로만 허용한다.
	Secret string `json:"-"`
	Masked string `json:"secret"`
}
