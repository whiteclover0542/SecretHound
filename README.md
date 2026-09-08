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

# 탐지된 키가 아직 살아있는지 발급처에 확인 (네트워크 사용)
secrethound scan ./myrepo --validate

# 이미 시크릿이 많은 레포에 처음 도입할 때: 현재 상태를 baseline으로 저장
secrethound scan ./myrepo --history --baseline-out secrethound-baseline.json

# 이후로는 baseline에 없는 새 시크릿만 보고
secrethound scan ./myrepo --history --baseline secrethound-baseline.json

# 탐지 룰 목록 확인 (어떤 룰이 검증 가능한지 함께 표시)
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
| `--validate` | 탐지한 키가 살아있는지 발급처 API에 확인 (기본 false, 네트워크 사용) |
| `--validate-timeout` | 검증 요청 하나당 제한 시간 (기본 5s) |
| `--baseline-out` | 현재 탐지 결과를 baseline 파일로 저장 |
| `--baseline` | 이 baseline 파일에 있는 시크릿은 결과에서 제외 (신규 항목만 보고). `--baseline-out`과 동시 사용 불가 |
| `--workers` | 정규식 매칭에 쓸 goroutine 수 (기본 0 = CPU 코어 수만큼 자동) |

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

### 키 유효성 검증 (`--validate`)

신뢰도 점수는 결국 "시크릿처럼 보이는가"에 대한 추정이다. `--validate` 를 켜면
탐지한 키를 **발급처에 직접 물어봐** 추정을 사실로 바꾼다.

```
CRITICAL  .env:3          github-pat  ghp_9m******2pXk  (신뢰도 100, GitHub 유효)
CRITICAL  app/old.py:12   stripe-...  sk_liv******mQ2z  (신뢰도 100, Stripe 폐기됨)
HIGH      README.md:8     aws-acce... AKIAIO******MPLE  (신뢰도 90, AWS STS 검증불가)
────────────────────────────────────────────────────────────
키 검증    유효 1, 폐기됨 1, 검증불가 1 (검증기 없는 룰 4건 제외)
           ! 살아있는 키 1건 — 파일을 지우기 전에 먼저 폐기하세요
```

**세 상태가 각각 무엇을 증명하는지가 중요하다.**

| 상태 | 뜻 | 증명되는 것 |
|---|---|---|
| 유효 | 발급처가 인증에 성공 | 실재하는 살아있는 키. 지금 위험하다 |
| 폐기됨 | 발급처가 인증을 거부 | 지금은 악용 불가. **탐지가 틀렸다는 뜻은 아니다** |
| 검증불가 | 네트워크 없음·레이트리밋·검증기 미지원 | 아무것도. 판단 보류다 |

"폐기됨"을 오탐으로 취급하지 않는 이유는, **폐기된 진짜 키와 애초에 키가 아니었던
문자열이 발급처 입장에서 똑같이 401이기 때문**이다. 이 둘은 응답으로 구분할 수 없다.
게다가 히스토리에 남은 폐기 키는 여전히 "이 레포는 시크릿을 커밋한 적이 있다"는
사실을 말해주므로 리포트에서 지우면 안 된다. 그래서 검증 결과는 신뢰도 점수를
건드리지 않고 별도 축으로 표시한다 — 신뢰도는 "탐지가 맞았는가", 검증은 "지금 위험한가"다.

살아있다고 확인된 키는 심각도보다 앞서 리포트 맨 위로 올라온다.
검증을 켠 사람이 알고 싶은 것은 "지금 당장 폐기해야 할 키"이기 때문이다.

**설계 제약** — 찾아낸 자격증명을 외부로 내보내는 기능이라 다음을 지킨다.

- **기본 비활성.** `--validate` 로만 켜진다. 스캔 대상 레포의 키를 외부로 보내도 되는지는
  사용자가 판단할 문제다
- **부작용 없는 최소 권한 엔드포인트만 호출한다.** AWS는 IAM 권한이 아예 필요 없는
  `sts:GetCallerIdentity`, GitHub은 `GET /user`, Slack은 `auth.test` 같은 신원 조회뿐이다.
  Slack Incoming Webhook은 조회 API가 없어 **일부러 잘못된 페이로드**를 보낸다 —
  살아있는 훅은 페이로드 검증 단계까지 가서 400을, 폐기된 훅은 그 전에 404를 주므로
  채널에는 아무 메시지도 올라가지 않는다
- **키 값은 로그·리포트 어디에도 남기지 않는다.** Telegram처럼 토큰을 URL 경로에 담는
  API가 있어 에러 문자열에 값이 섞여 나오므로, 기록 직전에 지운다
- **네트워크가 없으면 조용히 물러난다.** 연속 3회 연결 실패면 오프라인으로 보고 남은 검증을
  건너뛴다. 인터넷 없는 CI에서 탐지 건수만큼 타임아웃을 기다리는 일이 없도록 하기 위함이다.
  레이트리밋(429)은 `Retry-After` 를 존중해 한 번만 재시도한다
- **403은 폐기로 보지 않는다.** 권한 부족·레이트리밋·계정 정지가 모두 403이라
  구분할 수 없다. 살아있는 키를 죽었다고 보고하는 쪽이 판단 보류보다 훨씬 나쁜 오류다

**AWS만 방식이 다르다.** 다른 발급처는 토큰 하나를 헤더에 넣으면 되지만 AWS는
Access Key ID와 Secret Access Key로 요청에 **서명**해야 한다. 이 둘은 보통 서로 다른
줄·다른 파일에서 발견되므로, 같은 파일의 가장 가까운 줄을 우선해 짝을 찾고 없으면
레포 전체에서 찾는다. 짝을 잘못 지으면 STS가 `SignatureDoesNotMatch` 를 돌려주는데
이는 **Access Key ID 자체는 실재한다**는 뜻이라 "폐기됨"이 아닌 "검증불가"로 보고한다.
`ASIA` 로 시작하는 임시 자격증명은 세션 토큰 없이는 살아있어도 거부당하므로
아예 검증을 시도하지 않는다.

SigV4 서명은 표준 라이브러리(`hmac`/`sha256`)로 직접 구현했다. 이 한 번의 호출을 위해
aws-sdk-go-v2 전체를 의존성으로 끌어오면 단일 실행 바이너리라는 전제가 무너지기 때문이다.
구현은 AWS가 공개한 SigV4 테스트 벡터로 검증한다 — 서명이 틀리면 살아있는 키가
전부 "검증불가"가 되면서 에러는 한 줄도 안 나기 때문에, 이 테스트가 없으면
도구가 조용히 무용지물이 된다.

**검증 대상은 오탐 필터를 통과한 결과뿐이다.** 걸러낸 후보까지 물어보면 네트워크 호출이
몇 배로 늘고, 무엇보다 리포트에 나오지도 않을 값을 외부로 내보내게 된다.
같은 값이 여러 곳에서 발견되면 호출은 한 번만 한다.

현재 29개 룰 중 **17개**가 검증 대상이며 발급처는 14곳이다. 어떤 룰이 해당하는지는
`secrethound rules` 로 확인할 수 있다. Google API Key(키마다 활성화된
API가 달라 공통 엔드포인트가 없음), Twilio(짝이 되는 auth token 필요), Shopify(상점 도메인 필요),
JWT·PEM 개인키·DB 접속 문자열(발급처가 정해져 있지 않음)은 검증하지 않는다.

### 이 기능의 가장 큰 위험: 조용한 오작동

401 상태코드만으로 "폐기됨"을 판정하면 위험하다. 요청 자체가 잘못 만들어져 있어도
(헤더 이름 오타, API 버전 누락 등) 발급처는 살아있는 키에 똑같이 401을 준다.
그러면 **살아있는 키가 폐기됨으로 보고되는데, 죽은 키가 나오는 것은 정상적인 결과처럼
보이므로 아무도 눈치채지 못한다.**

그래서 14곳 중 상당수는 상태코드뿐 아니라 **발급처가 문서화한 인증 거부 응답의 본문
표식**까지 확인한다. 예를 들어 GitHub는 `401` + `"message":"Bad credentials"` 를 준다.
401이 와도 본문이 이 표식과 다르면 "폐기됨"이 아니라 "검증불가"로 남긴다 —
검증기 자체가 고장났을 가능성이 있으니 조용히 틀리는 것보다 모른다고 말하는 편이 낫다.

```bash
secrethound selfcheck
```

형식만 맞는 가짜 키를 14곳에 보내 이 표식이 여전히 유효한지 확인한다.
**진짜 자격증명은 필요 없다.** 발급처가 API를 바꾸면 여기서 먼저 드러나며,
매주 월요일 CI([selfcheck.yml](.github/workflows/selfcheck.yml))로 자동 실행된다.

```
[정상]   GitHub           HTTP 401 → revoked
[정상]   AWS STS          HTTP 403 → revoked
```

AWS가 401이 아니라 403을 준다는 것도 이 방식으로 확인했다 —
직접 조사하지 않고 짐작했다면 놓쳤을 부분이다.

> **셀프체크로 확인되지 않는 것도 있다.** 가짜 키는 항상 거부되어야 정상이므로
> 이 방식은 **거부 경로**만 검증한다. 살아있는 키가 실제로 `유효`로 판정되는
> **성공 경로**는 진짜 키로만 확인할 수 있다. 무료로 발급 가능한 7곳(AWS·GitHub·
> GitLab·Slack·Discord·Telegram·npm)은 실제 키로 성공 경로까지 확인했다.
> 이 과정에서 GitLab PAT의 신형식(마침표 포함 라우터블 토큰)이 구형 정규식에
> 안 걸리는 룰 버그를 실제로 찾아 고쳤다. 사업자 인증·유료 계정이 필요한
> 나머지 10곳(Stripe·Shopify 등)은 거부 경로만 확인된 상태다.

## Baseline (기존 레포 도입)

이미 시크릿이 여럿 커밋된 레포에 도입하면 첫 스캔에서 수십~수백 건이 쏟아진다.
그 상태로 CI에 붙이면 계속 빨간불이라 아무도 안 보게 된다. baseline은 "지금 보이는
것들은 이미 알고 있다"고 한 번 선언해두고, 이후로는 **새로 생긴 것만** 보고한다.

```bash
# 1. 도입 시점: 현재 상태를 baseline으로 저장
secrethound scan ./myrepo --history --baseline-out secrethound-baseline.json

# 2. 이후 CI에서: baseline에 없는 새 시크릿만 실패 처리
secrethound scan ./myrepo --history --baseline secrethound-baseline.json
```

식별은 파일 경로·룰·시크릿 값의 해시로 한다. **원본 값은 저장하지 않는다** —
baseline은 저장소에 커밋되는 파일이라, 원본을 넣으면 그 자체가 새로운 유출 경로가
된다. 해시 기반이라 다음 상황에서도 흔들리지 않는다.

- 파일 위쪽에 줄을 추가/삭제해 대상 줄 번호가 밀려도 같은 시크릿으로 인식한다
- 히스토리에 새 커밋이 쌓여도 이미 알고 있는 값은 계속 알고 있는 상태로 유지된다
- 같은 값이 여러 파일에 있으면 각각 별도로 추적한다 — 한 곳만 지우고 다른 곳을
  놓치는 일을 방지하기 위함이다

`--baseline`과 `--baseline-out`은 동시에 쓸 수 없다. 트리아지를 마치고 새로 나온
시크릿까지 "알고 있음"으로 편입하려면 `--baseline-out`을 다시 실행해 덮어쓰면 된다.

> 파일명을 `secrethound-baseline.json`(또는 `.secrethound-baseline.json`)으로
> 두면 기본 룰셋이 스캔 대상에서 자동으로 제외한다. 그러지 않으면 baseline 파일이
> 스캔 대상 디렉토리 안에 있는 경우 자기 자신도 매번 다시 스캔된다
> (내용이 해시뿐이라 위험하지는 않지만 파일 수 집계가 지저분해진다).

## 병렬 스캔

정규식 매칭(29개 룰)을 goroutine 워커 풀에 분산시킨다. 수집(파일 순회, `git log`
파싱)은 지금도 순서대로 처리한다 — 특히 히스토리 파싱은 diff 스트림을 상태를
유지하며 해석해야 하는 작업이라, 병렬화하면 정확성을 해칠 위험이 정확성 이득보다
크다고 판단했다. 그 결과로 나온 "파일 하나" 또는 "히스토리 한 줄" 단위의 정규식
매칭만 워커 풀에 맡긴다.

```bash
secrethound scan ./myrepo --workers 8   # 8개 goroutine
secrethound scan ./myrepo --workers 1   # 순차 처리와 동일
```

**실측 결과는 단계별로 다르다** (16코어 기준, express.js 5,678커밋 / 210파일).

| 단계 | workers=1 | 자동(16) | 비고 |
|---|---:|---:|---:|
| 파일 트리 스캔 | ~26ms | ~11ms | 약 2배. 파일 읽기(I/O)가 겹쳐 도는 효과 |
| 히스토리 스캔 | ~1,280ms | ~1,300ms | **차이 없음.** `git log` 서브프로세스 실행과 출력 파싱이 지배적 비용이라, 그 뒤에 오는 정규식 매칭을 병렬화해도 전체 시간에 거의 영향이 없다 |

즉 이 기능은 "느려서 고친 것"이 아니다 — 실측 이전에도 이미 충분히 빨랐다
(express 5,678커밋을 1.4초에 처리). 목적은 기획 단계에서 "Go를 고른 이유가
goroutine"이라고 적어둔 것과 실제 구현이 어긋나 있던 것을 메우는 데 가깝고,
측정해보니 정규식 매칭이 아니라 `git log` 자체가 병목이라는 것이 오히려 더
정확한 진단이 됐다.

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
    "duration_ms": 66,
    "validation": {
      "checked": 1,
      "valid": 1,
      "revoked": 0,
      "unknown": 0,
      "unsupported": 0,
      "offline": false
    }
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
      "validation": {
        "status": "valid",
        "provider": "GitHub"
      },
      "secret": "ghp_9m******2pXk"
    }
  ]
}
```

`summary.validation` 과 `findings[].validation` 은 `--validate` 를 켰을 때만 나타난다.
필드가 없는 것과 `status: "unknown"` 은 다른 뜻이다 — 전자는 검증을 안 한 것이고
후자는 검증했는데 판단할 수 없었다는 뜻이다.
`status` 는 `valid` \| `revoked` \| `unknown` 셋 중 하나이며, 판단 근거가 필요하면
`reason` 필드에 사람이 읽을 수 있는 설명이 함께 담긴다 (키 값은 절대 들어가지 않는다).

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
| `baseline-path` | (미사용) | 이 baseline 파일에 있는 시크릿은 제외하고 새로 생긴 것만 탐지 |

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
