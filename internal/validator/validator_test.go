package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestValidator는 모든 발급처 호출을 로컬 서버로 돌린다.
// 테스트가 실제 API를 때리면 네트워크 상태에 따라 결과가 흔들리고,
// 무엇보다 남의 서비스에 정체불명의 인증 요청을 보내게 된다.
func newTestValidator(t *testing.T, h http.Handler) *Validator {
	t.Helper()

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	v := New(Options{Timeout: 2 * time.Second, Workers: 2})
	v.client.Transport = srv.Client().Transport
	for name := range v.endpoints {
		v.endpoints[name] = srv.URL
	}
	return v
}

func TestRunReportsValidAndRevoked(t *testing.T) {
	v := newTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "live") {
			w.WriteHeader(http.StatusOK)
			return
		}
		// GitHub의 실제 인증 거부 응답 형태. classifyWith가 시그니처와 본문까지
		// 대조하므로, 상태코드만 흉내 내면 이 테스트가 실제 동작을 검증하지 못한다.
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))

	targets := []Target{
		{RuleID: "github-pat", Path: "a.go", Secret: "ghp_live0000000000000000000000000000"},
		{RuleID: "github-pat", Path: "b.go", Secret: "ghp_dead0000000000000000000000000000"},
		// 검증기가 없는 룰은 손대지 않는다.
		{RuleID: "generic-api-key", Path: "c.go", Secret: "whatever"},
	}

	results, stats := v.Run(t.Context(), targets)

	if results[0] == nil || results[0].Status != StatusValid {
		t.Errorf("살아있는 키를 유효로 봐야 한다: %+v", results[0])
	}
	if results[1] == nil || results[1].Status != StatusRevoked {
		t.Errorf("401은 폐기됨이어야 한다: %+v", results[1])
	}
	if results[2] != nil {
		t.Errorf("검증기 없는 룰에는 결과를 붙이면 안 된다: %+v", results[2])
	}

	if stats.Valid != 1 || stats.Revoked != 1 || stats.Unsupported != 1 {
		t.Errorf("집계가 맞지 않음: %+v", stats)
	}
	if results[0].Provider != "GitHub" {
		t.Errorf("provider 이름이 리포트에 필요하다: %q", results[0].Provider)
	}
}

// 403은 폐기가 아니다. 살아있는 키를 죽었다고 보고하는 쪽이 훨씬 나쁜 오류라서
// 권한 부족·레이트리밋·정지를 구분할 수 없는 응답은 전부 판단 보류로 남긴다.
func TestForbiddenIsNotRevoked(t *testing.T) {
	v := newTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	results, _ := v.Run(t.Context(), []Target{
		{RuleID: "github-pat", Secret: "ghp_000000000000000000000000000000000x"},
	})

	if results[0].Status != StatusUnknown {
		t.Errorf("403은 검증불가여야 한다: %+v", results[0])
	}
}

// 같은 값이 여러 곳에서 발견돼도 발급처에는 한 번만 물어본다.
// 히스토리 스캔에서 같은 키가 수십 번 나오는 일이 흔해서, 이게 없으면
// 레이트리밋에 걸리거나 발급처에 부담을 준다.
func TestDuplicateSecretsAreCheckedOnce(t *testing.T) {
	var calls atomic.Int32

	v := newTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	const secret = "ghp_same00000000000000000000000000000"
	targets := []Target{
		{RuleID: "github-pat", Path: "a.go", Secret: secret},
		{RuleID: "github-pat", Path: "b.go", Secret: secret},
		{RuleID: "github-pat", Path: "c.go", Secret: secret},
	}

	results, stats := v.Run(t.Context(), targets)

	if got := calls.Load(); got != 1 {
		t.Errorf("호출 %d회, 1회여야 한다", got)
	}
	for i, r := range results {
		if r == nil || r.Status != StatusValid {
			t.Errorf("results[%d] = %+v, 모두 같은 결과를 받아야 한다", i, r)
		}
	}
	if stats.Checked != 3 {
		t.Errorf("Checked = %d, 대상 수만큼 세야 한다", stats.Checked)
	}
}

// Slack은 인증 실패에도 HTTP 200을 준다. 본문을 읽지 않으면 죽은 토큰이 전부 유효가 된다.
func TestSlackUsesBodyNotStatusCode(t *testing.T) {
	v := newTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/auth.test") {
			t.Errorf("예상하지 못한 경로: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.Header.Get("Authorization"), "live") {
			w.Write([]byte(`{"ok":true,"user":"bot"}`))
			return
		}
		w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))

	results, _ := v.Run(t.Context(), []Target{
		{RuleID: "slack-token", Secret: "xoxb-live-0000000000-abcdefghij"},
		{RuleID: "slack-token", Secret: "xoxb-dead-0000000000-abcdefghij"},
	})

	if results[0].Status != StatusValid {
		t.Errorf("ok:true 는 유효여야 한다: %+v", results[0])
	}
	if results[1].Status != StatusRevoked {
		t.Errorf("invalid_auth 는 폐기됨이어야 한다: %+v", results[1])
	}
}

// Webhook은 조회 API가 없어서 일부러 잘못된 페이로드를 보낸다.
// 채널에 아무것도 올라가지 않는다는 것이 이 방식의 전제라, 요청 본문이
// 유효한 Slack 메시지가 아님을 함께 확인한다.
func TestSlackWebhookProbeHasNoSideEffect(t *testing.T) {
	v := newTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "json") {
			t.Errorf("JSON으로 보내면 메시지가 실제로 전송된다: %s", ct)
		}
		if strings.Contains(r.URL.Path, "dead") {
			http.Error(w, "no_service", http.StatusNotFound)
			return
		}
		http.Error(w, "invalid_payload", http.StatusBadRequest)
	}))

	results, _ := v.Run(t.Context(), []Target{
		{RuleID: "slack-webhook", Secret: "https://hooks.slack.com/services/T00000000/B00000000/live"},
		{RuleID: "slack-webhook", Secret: "https://hooks.slack.com/services/T00000000/B00000000/dead"},
	})

	if results[0].Status != StatusValid {
		t.Errorf("invalid_payload 는 훅이 살아있다는 뜻이다: %+v", results[0])
	}
	if results[1].Status != StatusRevoked {
		t.Errorf("no_service 는 폐기됨이어야 한다: %+v", results[1])
	}
}

// 인터넷이 없는 CI에서 finding 수만큼 타임아웃을 기다리면 스캔이 사실상 멈춘다.
func TestOfflineShortCircuits(t *testing.T) {
	// 연결을 즉시 거절하도록 서버를 띄웠다 바로 닫는다.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	v := New(Options{Timeout: time.Second, Workers: 1})
	for name := range v.endpoints {
		v.endpoints[name] = url
	}

	targets := make([]Target, 10)
	for i := range targets {
		targets[i] = Target{
			RuleID: "github-pat",
			Secret: "ghp_" + strings.Repeat("a", 32) + string(rune('0'+i)),
		}
	}

	results, stats := v.Run(t.Context(), targets)

	if !stats.Offline {
		t.Error("연속 네트워크 실패는 오프라인으로 판정돼야 한다")
	}
	if stats.Unknown != len(targets) {
		t.Errorf("Unknown = %d, 전부 검증불가여야 한다", stats.Unknown)
	}
	// 검증 실패가 탐지 결과를 지우면 안 된다. 결과는 남되 상태만 보류다.
	for i, r := range results {
		if r == nil {
			t.Fatalf("results[%d] 가 nil이면 안 된다", i)
		}
		if r.Status != StatusUnknown {
			t.Errorf("results[%d].Status = %s", i, r.Status)
		}
	}
}

// Telegram은 토큰을 URL 경로에 담아서, 실패하면 Go의 url.Error 가
// 에러 메시지에 토큰을 통째로 실어 보낸다. 그걸 그대로 리포트에 쓰면
// 리포트 파일 자체가 유출 경로가 된다.
func TestReasonNeverContainsSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	const token = "123456789:AAsecret0000000000000000000000000"

	v := New(Options{Timeout: time.Second, Workers: 1})
	for name := range v.endpoints {
		v.endpoints[name] = url
	}

	results, _ := v.Run(t.Context(), []Target{{RuleID: "telegram-bot-token", Secret: token}})

	if strings.Contains(results[0].Reason, token) {
		t.Fatalf("Reason에 토큰이 노출됨: %s", results[0].Reason)
	}
	if strings.Contains(results[0].Reason, "AAsecret") {
		t.Fatalf("Reason에 토큰 일부가 노출됨: %s", results[0].Reason)
	}
}

func TestRedactRemovesCredential(t *testing.T) {
	cred := credential{id: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG"}
	got := redact("Get \"https://x/AKIAIOSFODNN7EXAMPLE\": wJalrXUtnFEMI/K7MDENG failed", cred)

	if strings.Contains(got, "AKIA") || strings.Contains(got, "wJalr") {
		t.Errorf("자격증명이 남아 있음: %s", got)
	}
}

// 짧은 문자열까지 지우면 정상 문장이 훼손된다.
func TestRedactKeepsShortValues(t *testing.T) {
	got := redact("네트워크 오류로 검증 실패", credential{secret: "abc"})
	if got != "네트워크 오류로 검증 실패" {
		t.Errorf("문장이 훼손됨: %s", got)
	}
}

func TestRetryAfterRespectsHeader(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		header string
		want   time.Duration
		limit  bool
	}{
		{"레이트리밋 아님", 200, "", 0, false},
		{"대기 시간 지정", 429, "2", 2 * time.Second, true},
		{"헤더 없음", 429, "", 0, true},
		{"지나치게 긴 대기", 429, "600", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tt.code, Header: http.Header{}}
			if tt.header != "" {
				resp.Header.Set("Retry-After", tt.header)
			}

			got, limited := retryAfter(resp)
			if limited != tt.limit || got != tt.want {
				t.Errorf("got (%v, %v), want (%v, %v)", got, limited, tt.want, tt.limit)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		code int
		want Status
	}{
		{200, StatusValid},
		{204, StatusValid},
		{401, StatusRevoked},
		{403, StatusUnknown},
		{429, StatusUnknown},
		{500, StatusUnknown},
		{404, StatusUnknown},
	}

	for _, tt := range tests {
		if got, _ := classifyWith(nil, tt.code, nil); got != tt.want {
			t.Errorf("classifyWith(nil, %d) = %s, want %s", tt.code, got, tt.want)
		}
	}
}

// 요청이 잘못 만들어져도(오타 헤더 등) 발급처는 살아있는 키에 401을 줄 수 있다.
// 시그니처가 있는 발급처는 상태코드만이 아니라 본문 표식까지 맞아야 폐기로 판정해야
// 이런 조용한 오작동이 "폐기됨"으로 둔갑하지 않는다.
func TestClassifyWithSignatureRequiresBodyMatch(t *testing.T) {
	sig := &signature{code: 401, markers: []string{"Bad credentials"}}

	if got, _ := classifyWith(sig, 401, []byte(`{"message":"Bad credentials"}`)); got != StatusRevoked {
		t.Errorf("본문이 일치하면 폐기됨이어야 한다: %s", got)
	}

	got, reason := classifyWith(sig, 401, []byte(`{"message":"something else"}`))
	if got != StatusUnknown {
		t.Errorf("401이어도 본문이 다르면 검증불가여야 한다: %s", got)
	}
	if !strings.Contains(reason, "검증기 점검") {
		t.Errorf("이유에 점검 필요 안내가 없음: %q", reason)
	}
}

func TestRunWithNoTargets(t *testing.T) {
	v := New(Options{})
	results, stats := v.Run(context.Background(), nil)

	if len(results) != 0 || stats.Checked != 0 {
		t.Errorf("빈 입력에는 아무것도 하지 않아야 한다: %v %+v", results, stats)
	}
}

// 모든 검증 대상 룰이 등록된 발급처를 가리키는지 확인한다.
// 오타 하나로 룰이 조용히 검증에서 빠지는 것을 막는다.
func TestEveryRuleMapsToKnownProvider(t *testing.T) {
	eps := defaultEndpoints()

	for rule, name := range ruleProviders {
		p, ok := providers[name]
		if !ok {
			t.Errorf("룰 %s 가 없는 발급처 %q 를 가리킨다", rule, name)
			continue
		}
		if p.name != name {
			t.Errorf("발급처 %q 의 name 필드가 %q 로 어긋나 있다", name, p.name)
		}
		if p.label == "" {
			t.Errorf("발급처 %q 에 표시 이름이 없다", name)
		}
		if p.build == nil {
			t.Errorf("발급처 %q 에 요청 생성기가 없다", name)
		}
		if _, ok := eps[name]; !ok {
			t.Errorf("발급처 %q 의 베이스 URL이 없다", name)
		}
	}
}

func TestSupportedRulesReportsLabels(t *testing.T) {
	got := SupportedRules()

	if len(got) != len(ruleProviders) {
		t.Errorf("룰 수가 %d, %d여야 한다", len(got), len(ruleProviders))
	}
	if got["aws-access-key-id"] != "AWS STS" {
		t.Errorf("aws-access-key-id = %q", got["aws-access-key-id"])
	}
}
