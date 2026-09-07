# 설정 가이드

## 환경 변수

배포 전에 아래 값을 실제 자격증명으로 채워야 한다.

| 변수 | 형식 | 예시 |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | `AKIA` + 대문자/숫자 16자 | `AKIAIOSFODNN7EXAMPLE` |
| `GITHUB_TOKEN` | `ghp_` + 36자 | `ghp_YOUR_TOKEN_HERE_REPLACE_ME_000000` |
| `STRIPE_SECRET_KEY` | `sk_live_` + 24자 이상 | `sk_live_CHANGEME_CHANGEME_CHANGEME` |

## 발급 방법

1. AWS 콘솔 → IAM → 사용자 → 보안 자격 증명에서 액세스 키를 생성한다.
2. GitHub → Settings → Developer settings → Personal access tokens 에서 토큰을 발급한다.
3. 발급한 값은 절대 코드에 하드코딩하지 말고 시크릿 매니저에 저장한다.
