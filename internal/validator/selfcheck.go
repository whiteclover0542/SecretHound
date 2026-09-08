package validator

import (
	"context"
	"io"
	"sort"
	"strings"
)

// 셀프체크는 **진짜 자격증명 없이** 검증기가 아직 정상인지 확인한다.
//
// 검증기의 가장 위험한 고장은 조용하다. 요청이 잘못 만들어져 있으면 발급처는
// 살아있는 키에도 401을 주고, 그러면 리포트에는 "폐기됨"이 찍힌다.
// 죽은 키가 나오는 것은 정상적인 결과처럼 보이므로 아무도 이상함을 느끼지 못한다.
//
// 그래서 형식만 맞는 가짜 키를 보내 **인증 거부 응답의 형태**가 우리가 아는 것과
// 같은지 확인한다. 발급처가 API를 바꾸면 여기서 먼저 드러난다.
//
// 확인되지 않는 것: 성공 경로(2xx → 유효)다. 그건 진짜 키가 있어야 한다.

// probes는 셀프체크용 가짜 자격증명이다.
// 리터럴로 적으면 소스 자체가 시크릿 스캐너와 push protection에 걸리므로 조립해서 만든다.
// 전부 0으로 채워 어떤 발급처에서도 실재할 수 없는 값이다.
func probes() map[string]credential {
	return map[string]credential{
		"aws":           {id: fake("AKIA", 16), secret: strings.Repeat("0", 40)},
		"github":        {secret: fake("ghp_", 36)},
		"gitlab":        {secret: fake("glpat-", 20)},
		"slack":         {secret: fake("xoxb-", 40)},
		"slack-webhook": {secret: "https://hooks.slack.com/services/T00000000/B00000000/" + strings.Repeat("0", 24)},
		"stripe":        {secret: fake("sk_live_", 24)},
		"openai":        {secret: fake("sk-", 48)},
		"anthropic":     {secret: fake("sk-ant-api03-", 95)},
		"sendgrid":      {secret: "SG." + strings.Repeat("0", 22) + "." + strings.Repeat("0", 43)},
		"mailgun":       {secret: fake("key-", 32)},
		"npm":           {secret: fake("npm_", 36)},
		"discord":       {secret: "M" + strings.Repeat("0", 23) + "." + strings.Repeat("0", 6) + "." + strings.Repeat("0", 27)},
		"telegram":      {secret: strings.Repeat("0", 10) + ":AA" + strings.Repeat("0", 33)},
		"heroku":        {secret: "00000000-0000-0000-0000-000000000000"},
	}
}

type SelfCheckResult struct {
	Provider string
	Label    string

	// HasSignature는 상태코드뿐 아니라 **응답 본문까지** 확인하는 발급처인지다.
	// 본문을 보지 않으면 요청이 망가져서 생긴 거부와 진짜 거부를 구분할 수 없다.
	HasSignature bool
	// OK는 가짜 키가 제대로 거부됐는지다.
	// 가짜 키에 "유효"가 나오면 검증기가 아무 값이나 통과시키고 있다는 뜻이다.
	OK bool

	Code    int
	Status  Status
	Reason  string
	Excerpt string // 본문 앞부분. 시그니처를 채울 때 참고한다
	Err     string
}

const excerptLen = 160

// SelfCheck는 각 발급처에 가짜 키를 보내 인증 거부 응답의 형태를 확인한다.
func (v *Validator) SelfCheck(ctx context.Context) []SelfCheckResult {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)

	probe := probes()
	out := make([]SelfCheckResult, 0, len(names))

	for _, name := range names {
		p := providers[name]
		// 발급처 전용 inspect도 본문을 해석하므로 시그니처와 같은 역할을 한다.
		r := SelfCheckResult{
			Provider:     name,
			Label:        p.label,
			HasSignature: p.revoked != nil || p.inspect != nil,
		}

		cred, ok := probe[name]
		if !ok {
			r.Err = "셀프체크용 가짜 자격증명이 정의되지 않음"
			out = append(out, r)
			continue
		}

		code, body, err := v.probe(ctx, p, cred)
		if err != nil {
			r.Err = redact(err.Error(), cred)
			out = append(out, r)
			continue
		}

		r.Code = code
		r.Excerpt = excerpt(redact(string(body), cred))

		if p.inspect != nil {
			r.Status, r.Reason = p.inspect(code, body)
		} else {
			r.Status, r.Reason = classifyWith(p.revoked, code, body)
		}
		r.Reason = redact(r.Reason, cred)

		// 가짜 키를 보냈으므로 "폐기됨"이 나와야 정상이다.
		r.OK = r.Status == StatusRevoked

		out = append(out, r)
	}

	return out
}

func (v *Validator) probe(ctx context.Context, p provider, cred credential) (int, []byte, error) {
	req, err := p.build(ctx, v.endpoints[p.name], cred)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := v.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return resp.StatusCode, body, nil
}

// excerpt는 진단용으로 본문 앞부분만 한 줄로 만든다.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > excerptLen {
		return s[:excerptLen] + "…"
	}
	return s
}
