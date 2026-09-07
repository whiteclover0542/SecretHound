package secrethound

import _ "embed"

// 바이너리 단독 배포를 위해 기본 룰셋을 실행파일에 포함시킨다.
//
//go:embed rules/default.yaml
var DefaultRuleset []byte
