package secrethound

import _ "embed"

// 바이너리 단독 배포를 위해 기본 룰셋을 실행파일에 포함시킨다.
//
//go:embed rules/default.yaml
var DefaultRuleset []byte

// Dashboard는 리포트를 표로 보여주는 정적 페이지다. `--format html` 은 이 페이지에
// 리포트 JSON을 심어 한 장짜리 파일로 내보낸다 (reporter.WriteHTML 참조).
// 룰셋과 같은 이유로 내장한다 — 실행파일 하나만 받아도 동작해야 하기 때문이다.
//
//go:embed web/dashboard.html
var Dashboard []byte
