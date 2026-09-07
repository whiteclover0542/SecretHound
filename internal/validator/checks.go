package validator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// credential은 검증 요청 하나에 필요한 자격증명이다.
// 대부분의 API는 값 하나면 되지만, AWS는 Access Key ID와 Secret Access Key가
// 둘 다 있어야 서명할 수 있어 id 필드를 둔다.
type credential struct {
	id     string
	secret string
}

// provider는 발급처 하나에 대한 검증 방법이다.
//
// build가 만드는 요청은 반드시 **부작용이 없어야** 한다. 남의 계정에 대고
// 쓰기 작업을 하는 순간 이 도구는 스캐너가 아니라 공격 도구가 된다.
// 그래서 전부 신원 조회(whoami) 계열의 읽기 전용 엔드포인트만 쓴다.
type provider struct {
	name  string
	label string // 리포트에 표시할 이름
	build func(ctx context.Context, base string, cred credential) (*http.Request, error)
	// inspect가 nil이면 classify의 공통 규약을 쓴다.
	inspect func(code int, body []byte) (Status, string)
}

// ruleProviders는 룰 ID를 검증기에 연결한다.
// 여기 없는 룰은 검증기 미지원으로 남는다.
//
// 의도적으로 뺀 것들:
//   - google-api-key  : 키마다 활성화된 API가 달라 공통 검증 엔드포인트가 없다.
//     아무 API나 찔러보면 "그 API가 꺼져 있음"과 "키가 죽음"을 구분할 수 없다.
//   - twilio-api-key  : SID와 짝이 되는 auth token이 있어야 인증된다.
//   - shopify-access-token : 상점 도메인을 알아야 호출할 수 있는데 토큰에 들어있지 않다.
//   - jwt / private-key / db-connection-string / basic-auth-header / generic-api-key :
//     발급처가 정해져 있지 않다. 검증하려면 임의의 호스트에 접속해야 하므로 하지 않는다.
var ruleProviders = map[string]string{
	"aws-access-key-id":       "aws",
	"github-pat":              "github",
	"github-fine-grained-pat": "github",
	"github-oauth-token":      "github",
	"gitlab-pat":              "gitlab",
	"slack-token":             "slack",
	"slack-app-token":         "slack",
	"slack-webhook":           "slack-webhook",
	"stripe-secret-key":       "stripe",
	"openai-api-key":          "openai",
	"anthropic-api-key":       "anthropic",
	"sendgrid-api-key":        "sendgrid",
	"mailgun-api-key":         "mailgun",
	"npm-access-token":        "npm",
	"discord-bot-token":       "discord",
	"telegram-bot-token":      "telegram",
	"heroku-api-key":          "heroku",
}

func providerFor(ruleID string) (string, bool) {
	name, ok := ruleProviders[ruleID]
	return name, ok
}

// SupportedRules는 검증기가 붙어 있는 룰 ID 목록을 돌려준다.
// `secrethound rules` 가 어떤 룰이 검증 가능한지 표시하는 데 쓴다.
func SupportedRules() map[string]string {
	out := make(map[string]string, len(ruleProviders))
	for rule, name := range ruleProviders {
		out[rule] = providers[name].label
	}
	return out
}

// buildCredential은 finding에서 검증에 쓸 자격증명을 꺼낸다.
// 요청을 만들 수 없으면 그 이유를 함께 돌려준다. 이유는 리포트에 그대로 실리므로
// 키 값이 섞이지 않는 문장이어야 한다.
func buildCredential(t Target, paired string) (credential, string, bool) {
	if t.Secret == "" {
		return credential{}, "탐지된 값이 비어 있음", false
	}

	if t.RuleID == ruleAWSAccessKeyID {
		if isTemporaryAWSKey(t.Secret) {
			return credential{}, "STS 임시 자격증명이라 세션 토큰 없이는 검증할 수 없음", false
		}
		if paired == "" {
			return credential{}, "짝이 되는 AWS Secret Access Key를 찾지 못해 서명할 수 없음", false
		}
		return credential{id: t.Secret, secret: paired}, "", true
	}

	return credential{secret: t.Secret}, "", true
}

func defaultEndpoints() endpoints {
	return endpoints{
		"aws":           "https://sts.amazonaws.com",
		"anthropic":     "https://api.anthropic.com",
		"discord":       "https://discord.com",
		"github":        "https://api.github.com",
		"gitlab":        "https://gitlab.com",
		"heroku":        "https://api.heroku.com",
		"mailgun":       "https://api.mailgun.net",
		"npm":           "https://registry.npmjs.org",
		"openai":        "https://api.openai.com",
		"sendgrid":      "https://api.sendgrid.com",
		"slack":         "https://slack.com",
		"slack-webhook": "https://hooks.slack.com",
		"stripe":        "https://api.stripe.com",
		"telegram":      "https://api.telegram.org",
	}
}

// endpoints는 발급처 베이스 URL 목록이다.
// 테스트가 실제 API를 때리지 않도록 로컬 서버 주소로 갈아끼울 수 있게 분리했다.
type endpoints map[string]string

var providers = map[string]provider{
	"aws": {
		name:    "aws",
		label:   "AWS STS",
		build:   buildAWSRequest,
		inspect: inspectAWS,
	},

	"github": {
		name:  "github",
		label: "GitHub",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/user")
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+c.secret)
			req.Header.Set("Accept", "application/vnd.github+json")
			return req, nil
		},
	},

	"gitlab": {
		name:  "gitlab",
		label: "GitLab",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/api/v4/user")
			if err != nil {
				return nil, err
			}
			req.Header.Set("PRIVATE-TOKEN", c.secret)
			return req, nil
		},
	},

	// auth.test는 토큰의 소유자를 알려줄 뿐 아무것도 바꾸지 않는다.
	// Slack은 인증 실패에도 HTTP 200을 주고 본문의 ok 필드로 알리므로 별도 해석이 필요하다.
	"slack": {
		name:  "slack",
		label: "Slack",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/auth.test", nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+c.secret)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req, nil
		},
		inspect: inspectSlack,
	},

	// Incoming Webhook은 조회 API가 없다. 대신 **일부러 잘못된 페이로드**를 보낸다.
	// 살아있는 훅은 페이로드 검증 단계까지 가서 400 invalid_payload 를 주고,
	// 폐기된 훅은 그 전에 404 no_service 로 끊긴다. 어느 쪽이든 채널에는
	// 아무 메시지도 올라가지 않으므로 부작용이 없다.
	"slack-webhook": {
		name:  "slack-webhook",
		label: "Slack Webhook",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			target, err := rebase(base, c.secret)
			if err != nil {
				return nil, err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, target,
				strings.NewReader("secrethound-liveness-probe"))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "text/plain")
			return req, nil
		},
		inspect: inspectSlackWebhook,
	},

	"stripe": {
		name:  "stripe",
		label: "Stripe",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/v1/account")
			if err != nil {
				return nil, err
			}
			req.SetBasicAuth(c.secret, "")
			return req, nil
		},
	},

	"openai": {
		name:  "openai",
		label: "OpenAI",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/v1/models")
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+c.secret)
			return req, nil
		},
	},

	"anthropic": {
		name:  "anthropic",
		label: "Anthropic",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/v1/models")
			if err != nil {
				return nil, err
			}
			req.Header.Set("x-api-key", c.secret)
			req.Header.Set("anthropic-version", "2023-06-01")
			return req, nil
		},
	},

	"sendgrid": {
		name:  "sendgrid",
		label: "SendGrid",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/v3/scopes")
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+c.secret)
			return req, nil
		},
	},

	"mailgun": {
		name:  "mailgun",
		label: "Mailgun",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/v3/domains?limit=1")
			if err != nil {
				return nil, err
			}
			req.SetBasicAuth("api", c.secret)
			return req, nil
		},
	},

	"npm": {
		name:  "npm",
		label: "npm",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/-/whoami")
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+c.secret)
			return req, nil
		},
	},

	"discord": {
		name:  "discord",
		label: "Discord",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/api/v10/users/@me")
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bot "+c.secret)
			return req, nil
		},
	},

	// Telegram만 토큰이 URL 경로에 들어간다.
	// 이 때문에 에러 문자열에 토큰이 그대로 실릴 수 있어 redact가 반드시 필요하다.
	"telegram": {
		name:  "telegram",
		label: "Telegram",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			return get(ctx, base+"/bot"+c.secret+"/getMe")
		},
	},

	"heroku": {
		name:  "heroku",
		label: "Heroku",
		build: func(ctx context.Context, base string, c credential) (*http.Request, error) {
			req, err := get(ctx, base+"/account")
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+c.secret)
			req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
			return req, nil
		},
	},
}

func get(ctx context.Context, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
}

// rebase는 시크릿 자체가 URL인 경우(Slack Webhook) 경로만 남기고
// 호스트를 endpoints의 값으로 갈아끼운다. 테스트에서 로컬 서버로 돌리기 위한 장치이며,
// 기본 설정에서는 원래 호스트와 같은 값이라 동작이 바뀌지 않는다.
func rebase(base, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(base, "/") + u.EscapedPath(), nil
}

func inspectSlack(code int, body []byte) (Status, string) {
	if code != http.StatusOK {
		return classify(code, body)
	}

	var payload struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return StatusUnknown, "Slack 응답을 해석할 수 없음"
	}
	if payload.OK {
		return StatusValid, ""
	}

	switch payload.Error {
	case "invalid_auth", "token_revoked", "token_expired", "account_inactive":
		return StatusRevoked, "Slack이 토큰을 거부함 (" + payload.Error + ")"
	case "ratelimited":
		return StatusUnknown, "레이트리밋"
	}
	// Slack이 돌려준 오류 코드는 토큰 값이 아니라 상태 문자열이라 그대로 남겨도 안전하다.
	return StatusUnknown, "Slack 오류: " + payload.Error
}

// inspectSlackWebhook은 잘못된 페이로드를 보냈을 때의 응답으로 훅의 생존을 판별한다.
// 400은 "훅은 살아있고 본문만 틀렸다"는 뜻이라 유효로 본다.
func inspectSlackWebhook(code int, body []byte) (Status, string) {
	switch code {
	case http.StatusBadRequest:
		return StatusValid, "훅이 살아있음 (페이로드 검증 단계까지 도달)"
	case http.StatusNotFound, http.StatusGone, http.StatusForbidden:
		return StatusRevoked, "Slack이 훅을 알지 못함"
	case http.StatusOK:
		// 여기 오면 메시지가 실제로 전송됐을 수 있다. 설계상 도달하지 않아야 한다.
		return StatusValid, ""
	}
	return classify(code, body)
}
