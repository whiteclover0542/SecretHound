# secrethound

Git 레포에서 유출된 API 키와 시크릿을 탐지하는 도구

## 왜 필요한가

`.env` 대신 소스에 API 키를 하드코딩하고 그대로 커밋하는 사고는 흔하다.
더 큰 문제는 **나중에 키를 지워도 커밋 히스토리에는 그대로 남는다**는 점이다.
현재 파일만 봐서는 안전해 보이지만, 레포가 공개되는 순간 과거 커밋에서 키가 그대로 노출된다.

secrethound는 현재 파일과 **전체 커밋 히스토리**를 함께 스캔해서 이런 키를 찾아낸다.

```console
$ secrethound scan ./myrepo
탐지된 시크릿이 없습니다.

$ secrethound scan ./myrepo --history
CRITICAL  config.js@be880d7:1  github-pat  ghp_9m******2pXk  (신뢰도 100)
────────────────────────────────────────────────────────────
대상       ./myrepo
파일       1개 스캔, 0개 제외
커밋       2개 스캔
탐지       1건 (critical 1)
오탐 필터  0건 제외
소요       66ms
```

워킹트리에서는 이미 환경변수로 옮겨 깨끗하지만, 과거 커밋에 토큰이 남아있는 상황이다.

## 설치

```bash
go install github.com/whiteclover0542/secrethound/cmd/secrethound@latest
```

소스에서 빌드하려면:

```bash
git clone https://github.com/whiteclover0542/secrethound.git
cd secrethound
go build -o secrethound ./cmd/secrethound
```

룰셋은 바이너리에 내장되어 있어 별도 설정 파일 없이 바로 동작한다.

## 사용법

```bash
# 현재 디렉토리 스캔
secrethound scan

# 특정 경로 + 커밋 히스토리까지 스캔
secrethound scan ./myrepo --history

# 최근 100개 커밋만 스캔 (대형 레포)
secrethound scan ./myrepo --history --max-commits 100

# JSON으로 저장
secrethound scan ./myrepo --format json --output report.json

# 탐지 룰 목록 확인
secrethound rules
```

### 플래그

| 플래그 | 설명 |
|---|---|
| `--history` | git 커밋 히스토리까지 스캔 (과거에 지운 시크릿 탐지) |
| `--max-commits N` | 히스토리 스캔 대상 커밋 수 제한 (0 = 전체) |
| `-f, --format` | 출력 형식 `text` \| `json` (기본 `text`) |
| `-o, --output` | 결과를 파일로 저장 (기본: 표준 출력) |
| `-r, --rules` | 사용자 룰셋 파일 경로 (기본: 내장 룰셋) |
| `--no-color` | 색상 출력 비활성화 |
| `--report` | 일반 출력과 별개로 JSON 리포트를 파일에 저장 |
| `--exit-code` | 탐지 시 종료 코드 1 반환 (기본 true, CI 연동용) |

### 종료 코드

CI가 "시크릿 발견"과 "도구 실행 실패"를 구분할 수 있도록 나눠 두었다.

| 코드 | 의미 |
|:---:|---|
| 0 | 탐지된 시크릿 없음 |
| 1 | 시크릿 탐지됨 |
| 2 | 실행 실패 (잘못된 경로, 룰셋 오류 등) |

## 탐지 대상

AWS, GitHub, GitLab, Slack, Stripe, Google/GCP, OpenAI, Anthropic, SendGrid, Twilio,
npm, Shopify, Discord, Telegram, Azure, Heroku, PEM 개인키, JWT, DB 접속 문자열 등
**29개 룰**을 기본 제공하며, 전부 평가 코퍼스로 검증되어 있다.
전체 목록은 `secrethound rules` 로 확인할 수 있다.

Stripe publishable key나 Google OAuth Client ID처럼 **공개되도록 설계된 값은 탐지하지 않는다.**
유출이 아니므로 보고해봐야 노이즈만 된다 ([평가 결과](eval/README.md) 참조).

## 동작 방식

```
[레포 경로]
    │
    ├─▶ Repo Collector    현재 파일 순회 + git log -p 스트리밍 파싱
    │                     (바이너리·심볼릭 링크·제외 경로 필터링)
    ▼
  Detection Engine        키워드 프리필터 → 정규식 매칭 → 룰별 엔트로피 검증
    │
    ▼
  FP Filter               경로/값 컨텍스트로 신뢰도 감점, 임계값 미만 제외
    │
    ▼
  Reporter                심각도순 정렬 → 텍스트 / JSON 출력
```

### 오탐 처리

정규식만으로는 `AKIAXXXXXXXXXXXXXXXX` 같은 플레이스홀더도 전부 걸린다.
secrethound는 탐지 결과에 **신뢰도 점수(0~100)** 를 매겨 걸러낸다.

- 값 자체가 플레이스홀더 문구를 포함 (`example`, `changeme`, `xxxx`) → 감점
- 같은 문자가 8회 이상 반복 (마스킹된 값으로 추정) → 감점
- 테스트/예제 디렉토리, `.env.example` 등 → 감점
- 점수가 `min_confidence`(기본 50) 미만이면 리포트에서 제외

미탐은 오탐보다 손해가 크므로, 플레이스홀더 판별에는 무작위 문자열에 우연히
포함될 수 있는 짧은 단어를 쓰지 않는다.

### 히스토리 스캔

`git log -p -U0` 출력을 스트리밍으로 파싱해 **추가된 줄만** 검사한다.
삭제된 줄은 추가 시점에 이미 검사되므로, 이 방식으로 중복 없이 전체 히스토리를 덮는다.
hunk 헤더를 파싱해 해당 커밋 시점의 실제 줄 번호를 복원하고, 커밋 해시·작성자·날짜를
결과에 함께 기록한다.

같은 값이 여러 커밋에 걸쳐 있으면 **최초 유입 시점 하나로 묶어** 보고한다.
유출 대응에서 필요한 정보는 "언제 처음 들어왔는가"이기 때문이다.

```
MEDIUM  docs/config.rst@58a08a1:41   192b9b******bcbf  (신뢰도 60, 4곳, 현재도 존재)
MEDIUM  docs/config.rst@465922e:388  5f3523******5d2f  (신뢰도 60, 6곳)
```

`현재도 존재`는 워킹트리에도 남아있다는 뜻이다. 없으면 이미 지워졌고 히스토리에만 있는 값이라,
폐기 우선순위를 가릴 때 쓸 수 있다. 파일이 다르면 묶지 않는다 —
같은 키가 여러 파일에 하드코딩됐다면 전부 찾아 지워야 하기 때문이다.

## 룰셋 커스터마이징

`--rules` 로 직접 작성한 룰셋을 넘길 수 있다.
기본 룰셋은 [`rules/default.yaml`](rules/default.yaml) 참고.

```yaml
version: 1

rules:
  - id: my-internal-token
    description: 사내 서비스 토큰
    severity: critical
    keywords: [svc_]              # 이 문자열이 없는 줄은 정규식을 건너뛴다 (성능)
    regex: '\b(svc_[A-Za-z0-9]{32})\b'
    secret_group: 1               # 실제 시크릿이 담긴 캡처 그룹
    entropy: 4.0                  # 매치된 값의 최소 엔트로피 (선택)
    tags: [internal]

filter:
  min_confidence: 50
  exclude_paths:
    - '(^|/)vendor/'
  penalties:
    - id: sandbox-path
      target: path                # path | value
      pattern: '(^|/)sandbox/'
      score: -50
      reason: 샌드박스 디렉토리
  allowlist:
    rule_ids: []
    paths: []
    secrets: []
```

> **주의**: Go의 정규식은 RE2 엔진이라 lookahead `(?=)`, lookbehind `(?<=)`,
> 백레퍼런스 `\1` 을 지원하지 않는다. `(?i)` 와 `\b` 는 사용 가능하다.

## JSON 출력

대시보드나 CI가 소비할 수 있는 고정 스키마로 출력한다.
**원본 시크릿 값은 포함하지 않는다** — 리포트 파일이 또 다른 유출 경로가 되면 안 되기 때문이다.

```json
{
  "tool": "secrethound",
  "target": "./myrepo",
  "scanned_at": "2026-09-07T16:33:05+09:00",
  "summary": {
    "files_scanned": 1,
    "commits_scanned": 2,
    "findings": 1,
    "filtered_out": 0,
    "by_severity": { "critical": 1 },
    "duration_ms": 66
  },
  "findings": [
    {
      "rule_id": "github-pat",
      "severity": "critical",
      "path": "config.js",
      "commit": "be880d7...",
      "author": "김개발",
      "line": 1,
      "confidence": 100,
      "occurrences": 3,
      "in_worktree": false,
      "secret": "ghp_9m******2pXk"
    }
  ]
}
```

## GitHub Actions

PR에 시크릿이 들어오면 CI를 실패시킨다.

```yaml
name: secret-scan

on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0      # --history 를 쓰려면 전체 히스토리가 필요하다
      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"
      - uses: whiteclover0542/secrethound@main
        with:
          history: "true"
```

| 입력 | 기본값 | 설명 |
|---|---|---|
| `path` | `.` | 스캔할 경로 |
| `history` | `false` | 커밋 히스토리까지 스캔 |
| `max-commits` | `0` | 히스토리 스캔 커밋 수 제한 |
| `rules` | (내장 룰셋) | 사용자 룰셋 경로 |
| `fail-on-detection` | `true` | 탐지 시 워크플로 실패 여부 |
| `report-path` | (임시 파일) | JSON 리포트 저장 경로 |

출력 `findings` 로 탐지 건수를 받을 수 있다.

> `fetch-depth: 0` 을 빠뜨리면 checkout이 얕은 클론을 만들어 `--history` 가
> 최근 커밋만 보게 된다. 히스토리 스캔을 쓸 때는 반드시 필요하다.

## 정확도 측정

레이블된 코퍼스(실제 시크릿 32건 + 오탐 유발 케이스 28건)로 정확도를 측정한다.

```bash
go run ./eval                  # precision / recall / F1
go run ./eval --coverage       # 룰별 검증 여부
go run ./eval --history        # 히스토리 스캔 시나리오
go run ./eval --tool gitleaks  # gitleaks 비교
```

| 도구 | Precision | Recall | F1 |
|---|---:|---:|---:|
| secrethound | 1.000 | 1.000 | 1.000 |
| gitleaks v8.30.1 | 0.875 | 0.875 | 0.875 |

측정 과정에서 오탐 4건, 미탐 5건, 심각도 오분류 1건, 도달 불가능한 룰 1개,
그리고 **정답 레이블 자체의 오류 1건**을 찾아 고쳤다.

> **이 표를 "더 낫다"로 읽으면 안 된다.** 코퍼스를 직접 만들고 그 코퍼스에 맞춰
> 룰을 고쳤으므로 과적합이며, 코퍼스에 넣을 서비스도 내 룰셋 위주로 골랐다.
> 공정한 비교에는 제3자 코퍼스가 필요하다.
> 편향의 구체적인 내용과 측정 방법은 [eval/README.md](eval/README.md)에 정리했다.

## 개발

```bash
go test ./...      # 테스트
go vet ./...       # 정적 분석
gofmt -l .         # 포맷 검사
go run ./eval      # 정확도 측정
```

## 라이선스

MIT
