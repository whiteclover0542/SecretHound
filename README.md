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

## 빠른 시작

### 터미널을 쓰지 않는다면 (Windows)

1. [Releases](https://github.com/whiteclover0542/secrethound/releases)에서
   `secrethound_..._windows_amd64.zip` 을 받는다
2. 압축을 푼다
3. 안에 있는 **시크릿 검사하기** 아이콘을 두 번 클릭하고, 창에서 검사할 폴더를 고른다

검사가 끝나면 결과가 브라우저에 자동으로 열린다. 폴더를 아이콘 위로 끌어다 놓아도 된다.
Go 설치도, 명령어 입력도 필요 없다.

> 처음 실행할 때 "Windows의 PC 보호" 경고가 뜨면 **추가 정보 → 실행** 을 누르면 된다.
> 유료 코드 서명 인증서가 없어서 나오는 경고이지, 악성 코드가 발견됐다는 뜻이 아니다.

### 터미널을 쓴다면

```console
$ secrethound check ./myrepo
검사한 곳   ./myrepo
검사 범위   지금 있는 파일 1개 + 커밋 2개
결과        유출된 것으로 보이는 키 1건 (critical 1)

! 파일에서 지우기 전에 발급처에서 키를 먼저 폐기(revoke)하세요.
  지우기만 하면 키는 그대로 살아있습니다. 폐기 절차는 리포트에 있습니다.

저장된 리포트
  C:\work\secrethound-report.html
  C:\work\secrethound-report.md
```

`check` 하나로 다음이 전부 끝난다.

- 대상이 git 저장소면 **커밋 히스토리까지** 함께 검사한다
- 결과를 HTML과 마크다운 두 형식으로 저장한다
- HTML 리포트를 기본 브라우저로 연다

폴더를 생략하면 지금 있는 폴더를 검사한다. 플래그를 직접 조립하거나 CI에 붙일 때는
종료 코드를 나눠 주는 [`scan`](#사용법) 을 쓴다.

**결과 읽기** — 심각도(`CRITICAL`/`HIGH`/...), 위치(`파일:줄번호`), 키 종류, 값의 일부
(마스킹됨)가 표로 나온다. "유출된 시크릿을 찾지 못했습니다"만 나오면 정상이다.

## 설치

**실행 파일 내려받기 (Go 필요 없음)** —
[Releases](https://github.com/whiteclover0542/secrethound/releases)에서 OS에 맞는 파일을 받는다.
Windows용 zip에는 실행 파일과 함께 더블클릭용 바로가기가 들어있다.

**Go가 있다면**

```bash
go install github.com/whiteclover0542/secrethound/cmd/secrethound@latest
```

**소스에서 빌드**

```bash
git clone https://github.com/whiteclover0542/secrethound.git
cd secrethound
go build -o secrethound ./cmd/secrethound
```

룰셋과 리포트 페이지는 바이너리에 내장되어 있어 별도 파일 없이 바로 동작한다.

> **Windows PowerShell 사용자**: 소스에서 직접 빌드했다면 `secrethound scan ...` 이
> 아니라 앞에 `.\` 를 붙인 `.\secrethound.exe scan ...` 으로 실행해야 한다. PowerShell은
> 현재 폴더의 실행 파일을 자동으로 찾지 않는다 (릴리스 zip이나 `go install` 로 설치했다면
> 해당 없음).

## 사용법

커맨드는 둘로 나뉜다. `check` 는 사람이 결과를 눈으로 보는 용도로, 플래그 없이 항상
같은 일을 한다. `scan` 은 플래그로 세부를 제어하고 종료 코드로 탐지 여부를 알리는
CI용이다. 시크릿을 찾아도 `check` 는 0으로 끝나고 `scan` 은 1로 끝난다.

```bash
# 폴더 하나를 검사하고 결과를 브라우저로 열기 (히스토리 포함 여부는 알아서 판단)
secrethound check ./myrepo

# 검사만 하고 브라우저는 열지 않기
secrethound check ./myrepo --no-open

# 리포트를 다른 폴더에 저장하기
secrethound check ./myrepo --out ./reports
```

아래는 `scan` 으로 상황별 세부 제어가 필요할 때 쓰는 명령이다.

```bash
# 마크다운 리포트를 만들어 바로 열기
secrethound scan ./myrepo --history --format md --open

# 최근 100개 커밋만 스캔 (대형 레포라 히스토리 스캔이 오래 걸릴 때)
secrethound scan ./myrepo --history --max-commits 100

# 탐지된 키가 아직 살아있는지 발급처에 직접 확인 (네트워크 사용, 기본은 확인 안 함)
secrethound scan ./myrepo --validate

# 이미 시크릿이 많이 섞여 있는 레포에 처음 도입할 때: 지금 상태를 baseline으로 저장
secrethound scan ./myrepo --history --baseline-out secrethound-baseline.json

# 이후로는 baseline에 없는 새로 추가된 시크릿만 보고
secrethound scan ./myrepo --history --baseline secrethound-baseline.json

# 탐지 룰 목록 확인 (어떤 룰이 --validate 로 검증 가능한지 함께 표시)
secrethound rules
```

### 전체 플래그

거의 다 쓰지 않아도 되고, 필요할 때 찾아보는 참고용 표다.

| 플래그 | 설명 |
|---|---|
| `--history` | git 커밋 히스토리까지 스캔 (과거에 지운 시크릿 탐지) |
| `--max-commits N` | 히스토리 스캔 대상 커밋 수 제한 (0 = 전체) |
| `-f, --format` | 출력 형식 `text` \| `json` \| `md` \| `html` (기본 `text`) |
| `-o, --output` | 결과를 파일로 저장 (기본: 표준 출력) |
| `--open` | 저장한 리포트를 기본 브라우저로 연다 (`--output` 생략 시 현재 폴더에 만든다) |
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
npm, Shopify, Discord, Telegram, Azure, Heroku, PEM 개인키, JWT, DB 접속 문자열, 그리고
공공데이터포털·카카오·네이버·NCP·토스페이먼츠·포트원 등 **37개 룰**을 기본 제공하며,
전부 평가 코퍼스로 검증되어 있다. 전체 목록은 `secrethound rules` 로 확인할 수 있다.

국내 서비스는 해외 서비스와 달리 값만 보고 발급처를 알 수 있는 접두사를 공식화한 곳이
드물다. 그래서 형식이 문서로 확인되는 것(카카오 `KakaoAK`, 토스페이먼츠 `live_sk_`)만
접두사로 잡고, 나머지는 변수·헤더 이름(`serviceKey`, `X-Naver-Client-Secret`)을 앵커로
삼는다. 자릿수를 추측한 접두사 룰은 추측이 틀렸을 때 조용히 아무것도 못 잡지만, 이름은
그 서비스를 쓰는 코드라면 반드시 나오고 바뀌지도 않기 때문이다. 대신 값이 이름과 다른
줄에 있으면 놓친다 — 그 경우는 `generic-api-key`가 medium으로 받는다.

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

### 히스토리 스캔

`git log -p -U0` 출력을 스트리밍으로 파싱해 **추가된 줄만** 검사하며, 커밋
해시·작성자·날짜를 함께 기록한다. 같은 값이 여러 커밋에 걸쳐 있으면 **최초 유입
시점 하나로 묶어** 보고한다.

```
MEDIUM  docs/config.rst@58a08a1:41   192b9b******bcbf  (신뢰도 60, 4곳, 현재도 존재)
MEDIUM  docs/config.rst@465922e:388  5f3523******5d2f  (신뢰도 60, 6곳)
```

`현재도 존재`는 워킹트리에도 남아있다는 뜻이다. 없으면 이미 지워졌고 히스토리에만 있는 값이라,
폐기 우선순위를 가릴 때 쓸 수 있다. 파일이 다르면 묶지 않는다 —
같은 키가 여러 파일에 하드코딩됐다면 전부 찾아 지워야 하기 때문이다.

### 키 유효성 검증 (`--validate`)

신뢰도 점수는 "시크릿처럼 보이는가"에 대한 추정이다. `--validate`를 켜면
탐지한 키를 발급처에 직접 물어봐 이를 사실로 바꾼다.

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

"폐기됨"을 오탐으로 취급하지 않는 이유는, 폐기된 진짜 키와 애초에 키가 아니었던
문자열이 발급처 입장에서 똑같이 401이라 응답만으로 구분할 수 없기 때문이다.
검증 결과는 신뢰도 점수를 건드리지 않고 별도 축으로 표시한다 — 신뢰도는 "탐지가
맞았는가", 검증은 "지금 위험한가"다. 살아있다고 확인된 키는 심각도보다 앞서
리포트 맨 위로 올라온다.

**설계 제약** — 찾아낸 자격증명을 외부로 내보내는 기능이라 다음을 지킨다.

- **기본 비활성.** `--validate` 로만 켜진다
- **부작용 없는 최소 권한 엔드포인트만 호출한다.** AWS `sts:GetCallerIdentity`,
  GitHub `GET /user`, Slack `auth.test` 같은 신원 조회뿐이다. Slack Incoming
  Webhook처럼 조회 API가 없는 경우 일부러 잘못된 페이로드를 보내 400/404로만 구분한다
- **키 값은 로그·리포트 어디에도 남기지 않는다**
- **네트워크가 없으면 조용히 물러난다.** 연속 3회 연결 실패 시 오프라인으로 보고
  남은 검증을 건너뛴다. 레이트리밋(429)은 `Retry-After` 를 존중해 한 번만 재시도한다
- **403은 폐기로 보지 않는다.** 권한 부족·레이트리밋과 구분할 수 없으므로 검증불가로 처리한다

**AWS만 방식이 다르다.** Access Key ID와 Secret Access Key로 요청에 직접 서명해야 해서,
같은 파일에서 가장 가까운 짝을 찾아 SigV4로 서명한다(표준 라이브러리로 직접 구현,
AWS 공개 테스트 벡터로 검증). 서명이 틀리면 STS가 `SignatureDoesNotMatch` 를
주는데 이는 Access Key ID 자체는 실재한다는 뜻이라 "폐기됨"이 아닌 "검증불가"로
보고한다. `ASIA` 로 시작하는 임시 자격증명은 근처에서 세션 토큰까지 함께 찾은
경우에만 `X-Amz-Security-Token` 을 포함해 검증한다.

검증 대상은 오탐 필터를 통과한 결과뿐이며, 같은 값이 여러 곳에서 발견되면 호출은
한 번만 한다. 현재 37개 룰 중 **17개**가 검증 대상이며 발급처는 14곳이다
(`secrethound rules` 로 확인 가능). Google API Key·Twilio·Shopify·JWT·PEM
개인키·DB 접속 문자열 등은 공통 엔드포인트가 없거나 발급처가 정해져 있지 않아
검증하지 않는다.

**주의: 401만으로 폐기를 판정하면 위험하다.** 요청 자체가 잘못 만들어져도(헤더
오타, API 버전 누락 등) 발급처는 살아있는 키에 똑같이 401을 줄 수 있고, 그러면
살아있는 키가 조용히 폐기됨으로 보고된다. 그래서 다수 발급처는 상태코드뿐 아니라
문서화된 인증 거부 응답의 **본문 표식**까지 확인하고, 표식이 다르면 "폐기됨"이
아니라 "검증불가"로 남긴다.

```bash
secrethound selfcheck
```

형식만 맞는 가짜 키를 14곳에 보내 이 표식이 여전히 유효한지 확인한다
(진짜 자격증명 불필요). 매주 월요일 CI([selfcheck.yml](.github/workflows/selfcheck.yml))로
자동 실행된다.

> selfcheck는 가짜 키가 항상 거부되는 **거부 경로**만 검증한다. 살아있는 키가
> `유효`로 판정되는 **성공 경로**는 무료 발급 가능한 7곳(AWS·GitHub·GitLab·Slack·
> Discord·Telegram·npm)만 진짜 키로 확인했다. 사업자 인증·유료 계정이 필요한
> 나머지 10곳(Stripe·Shopify 등)은 거부 경로만 확인된 상태다.

## Baseline (기존 레포 도입)

이미 시크릿이 여럿 커밋된 레포는 첫 스캔에서 수십~수백 건이 쏟아진다. baseline은
"지금 보이는 것들은 이미 알고 있다"고 선언해두고, 이후로는 **새로 생긴 것만** 보고한다.

```bash
# 1. 도입 시점: 현재 상태를 baseline으로 저장
secrethound scan ./myrepo --history --baseline-out secrethound-baseline.json

# 2. 이후 CI에서: baseline에 없는 새 시크릿만 실패 처리
secrethound scan ./myrepo --history --baseline secrethound-baseline.json
```

식별은 파일 경로·룰·시크릿 값의 해시로 한다 (**원본 값은 저장하지 않는다** — baseline은
저장소에 커밋되는 파일이므로). 줄 번호가 밀려도, 히스토리에 새 커밋이 쌓여도 흔들리지
않으며, 같은 값이 여러 파일에 있으면 각각 별도로 추적한다.

`--baseline`과 `--baseline-out`은 동시에 쓸 수 없다. 트리아지를 마치고 새로 나온
시크릿까지 편입하려면 `--baseline-out`을 다시 실행해 덮어쓰면 된다.

> 파일명을 `secrethound-baseline.json`(또는 `.secrethound-baseline.json`)으로
> 두면 기본 룰셋이 스캔 대상에서 자동으로 제외한다.

## 병렬 스캔

정규식 매칭(37개 룰)을 goroutine 워커 풀에 분산시킨다. 파일 순회와 `git log` 파싱
같은 수집 단계는 상태를 유지하며 순서대로 해석해야 해서 병렬화하지 않는다.

```bash
secrethound scan ./myrepo --workers 8   # 8개 goroutine
secrethound scan ./myrepo --workers 1   # 순차 처리와 동일
```

**실측 결과는 단계별로 다르다** (16코어 기준, express.js 5,678커밋 / 210파일).

| 단계 | workers=1 | 자동(16) | 비고 |
|---|---:|---:|---:|
| 파일 트리 스캔 | ~26ms | ~11ms | 약 2배. 파일 읽기(I/O)가 겹쳐 도는 효과 |
| 히스토리 스캔 | ~1,280ms | ~1,300ms | **차이 없음.** `git log` 서브프로세스 실행과 출력 파싱이 지배적 비용이라, 그 뒤에 오는 정규식 매칭을 병렬화해도 전체 시간에 거의 영향이 없다 |

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
    remediation: >-              # 폐기(revoke) 절차 안내 (선택). 리포트의 "대응 방법" 절에 실린다
      사내 토큰 발급 시스템에서 해당 서비스 토큰을 즉시 재발급하라.

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
      "remediation": "GitHub → Settings → Developer settings → Personal access tokens에서 해당 토큰을 Delete(폐기).",
      "history_cleanup": "git filter-repo --path 'config.js' --invert-paths",
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

`findings[].remediation` 은 이 종류의 키를 발급처에서 폐기하는 절차 안내다 (룰셋의
`remediation` 필드에서 옮겨온다). `findings[].history_cleanup` 은 git 히스토리(과거
커밋)에서 발견된 경우에만 채워지며, 해당 파일을 히스토리 전체에서 제거하는
`git filter-repo` 명령이다 — **키를 지우기 전에 반드시 먼저 폐기부터** 해야 한다.
히스토리만 지워도 키 자체는 여전히 유효하기 때문이다. 텍스트 출력에서는 리포트
맨 아래 "대응 방법" 절에 이 정보가 룰·파일 단위로 한 번씩만 모여서 나온다.

## 리포트

같은 결과를 네 가지 형식으로 낸다. 무엇을 쓸지는 **누가 읽느냐**로 갈린다.

| 형식 | 쓰임 |
|---|---|
| `text` | 터미널에서 바로 확인 (기본) |
| `html` | 리포트가 심어진 대시보드 한 장. 열면 바로 표가 뜬다 |
| `md` | 메모장·노션·깃허브에 그대로 붙여넣기 |
| `json` | CI·다른 도구가 소비 (스키마 고정) |

```bash
secrethound scan ./myrepo --history --format html --output report.html --open
```

`--format html` 은 [`web/dashboard.html`](web/dashboard.html) 페이지에 리포트 JSON을
함께 심어 **파일 하나**로 내보낸다. 그래서 JSON을 따로 저장했다가 대시보드에 끌어다
놓는 과정이 필요 없다 — 만들어진 파일을 열면 바로 표가 뜬다. `check` 는 이 형식을
기본으로 만들고 브라우저까지 열어준다.

`web/dashboard.html` 을 그냥 열면 예전처럼 JSON 파일을 끌어다 놓는 화면이 나온다.
두 경로가 같은 페이지를 쓰므로 화면 코드를 두 벌 유지하지 않는다.

페이지는 순수 정적 파일이라 리포트 내용이 어디로도 전송되지 않고, 로컬 브라우저
안에서만 렌더링된다.

- 요약 카드(탐지 건수, 스캔한 파일/커밋 수, 심각도 분포, 검증 요약)
- 살아있는 키가 있으면 배너로 즉시 경고
- CLI와 같은 "대응 방법" 절 — 룰별 폐기 안내와 히스토리 정리(`git filter-repo`) 명령을
  한 번씩만 모아서 보여주고, 명령은 클립보드로 복사 가능
- 심각도 필터, 경로/룰 검색, 히스토리 발견만 보기, 컬럼 정렬
- 행을 클릭하면 설명·태그·엔트로피·검증 상세·개별 대응 정보가 펼쳐짐

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
      - uses: whiteclover0542/secrethound@main
        with:
          history: "true"
```

액션은 릴리스에 올라간 실행 파일을 받아 쓰므로 `actions/setup-go` 가 필요 없다.
받지 못하는 경우에만 소스 빌드로 되돌아가는데, 그때는 Go가 있어야 한다.

| 입력 | 기본값 | 설명 |
|---|---|---|
| `path` | `.` | 스캔할 경로 |
| `history` | `false` | 커밋 히스토리까지 스캔 |
| `max-commits` | `0` | 히스토리 스캔 커밋 수 제한 |
| `rules` | (내장 룰셋) | 사용자 룰셋 경로 |
| `fail-on-detection` | `true` | 탐지 시 워크플로 실패 여부 |
| `report-path` | (임시 파일) | JSON 리포트 저장 경로 |
| `baseline-path` | (미사용) | 이 baseline 파일에 있는 시크릿은 제외하고 새로 생긴 것만 탐지 |
| `version` | (최신 릴리스) | 사용할 secrethound 릴리스 태그 |

출력 `findings` 로 탐지 건수를 받을 수 있다.

> `fetch-depth: 0` 을 빠뜨리면 checkout이 얕은 클론을 만들어 `--history` 가
> 최근 커밋만 보게 된다. 히스토리 스캔을 쓸 때는 반드시 필요하다.

## 정확도 측정

레이블된 코퍼스(실제 시크릿 45건 + 오탐 유발 케이스 34건)로 정확도를 측정한다.

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

> 이 표는 "더 낫다"가 아니라 참고용이다 — 코퍼스를 직접 만들고 그에 맞춰 룰을
> 고쳤으므로 과적합이다. 공정한 비교에는 제3자 코퍼스가 필요하다. 자세한 내용은
> [eval/README.md](eval/README.md) 참고.

## 개발

```bash
go test ./...      # 테스트
go vet ./...       # 정적 분석
gofmt -l .         # 포맷 검사
go run ./eval      # 정확도 측정
```

## 라이선스

MIT
