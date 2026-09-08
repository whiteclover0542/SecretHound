package validator

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// AWS가 공개한 SigV4 테스트 벡터(get-vanilla)로 서명 구현을 검증한다.
//
// 이 테스트가 없으면 서명 오류를 알아챌 방법이 없다. 서명이 틀리면 STS가
// SignatureDoesNotMatch를 돌려주고, 우리 코드는 그것을 "검증불가"로 처리하기 때문에
// 살아있는 키를 하나도 못 잡으면서 에러는 한 줄도 안 나는 상태가 된다.
func TestSignV4MatchesAWSTestVector(t *testing.T) {
	const (
		secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		want   = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	)

	now, err := time.Parse("20060102T150405Z", "20150830T123600Z")
	if err != nil {
		t.Fatalf("테스트 시각 파싱 실패: %v", err)
	}

	got := signV4(secret, sigv4Input{
		method:  http.MethodGet,
		uri:     "/",
		region:  "us-east-1",
		service: "service",
		now:     now,
		headers: []sigv4Header{
			{"x-amz-date", "20150830T123600Z"},
			{"host", "example.amazonaws.com"},
		},
	})

	if got.signature != want {
		t.Errorf("signature\n got %s\nwant %s", got.signature, want)
	}
	if got.signedHeaders != "host;x-amz-date" {
		t.Errorf("signedHeaders = %q, want %q", got.signedHeaders, "host;x-amz-date")
	}
	if want := "20150830/us-east-1/service/aws4_request"; got.scope != want {
		t.Errorf("scope = %q, want %q", got.scope, want)
	}
}

func TestBuildAWSRequestSignsHeaders(t *testing.T) {
	req, err := buildAWSRequest(t.Context(), "https://sts.example.com",
		credential{id: "AKIAIOSFODNN7EXAMPLE", secret: "secret"})
	if err != nil {
		t.Fatalf("요청 생성 실패: %v", err)
	}

	auth := req.Header.Get("Authorization")
	for _, want := range []string{
		"AWS4-HMAC-SHA256 ",
		"Credential=AKIAIOSFODNN7EXAMPLE/",
		"SignedHeaders=content-type;host;x-amz-date",
		"Signature=",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization 헤더에 %q 가 없음: %s", want, auth)
		}
	}

	// 서명한 헤더가 실제로 요청에 실려 있어야 서명이 성립한다.
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date 헤더가 비어 있음")
	}
	if req.Header.Get("Content-Type") != stsContentType {
		t.Errorf("Content-Type = %q", req.Header.Get("Content-Type"))
	}
}

// 세션 토큰이 있으면 요청 헤더에도 실려야 하고, SignedHeaders 목록에도 포함돼야
// 한다 — 헤더만 붙이고 서명 대상에서 빠지면 STS가 헤더 변조로 보고 거부할 수 있다.
func TestBuildAWSRequestWithSessionTokenSignsHeader(t *testing.T) {
	req, err := buildAWSRequest(t.Context(), "https://sts.example.com",
		credential{id: "ASIAIOSFODNN7EXAMPLE", secret: "secret", sessionToken: "example-session-token"})
	if err != nil {
		t.Fatalf("요청 생성 실패: %v", err)
	}

	if got := req.Header.Get("X-Amz-Security-Token"); got != "example-session-token" {
		t.Errorf("X-Amz-Security-Token 헤더 = %q, want %q", got, "example-session-token")
	}

	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token") {
		t.Errorf("세션 토큰이 SignedHeaders에 없음: %s", auth)
	}
}

// 세션 토큰이 없으면(장기 자격증명) 기존과 동일하게 헤더가 붙지 않아야 한다 —
// 회귀 확인용.
func TestBuildAWSRequestWithoutSessionTokenOmitsHeader(t *testing.T) {
	req, err := buildAWSRequest(t.Context(), "https://sts.example.com",
		credential{id: "AKIAIOSFODNN7EXAMPLE", secret: "secret"})
	if err != nil {
		t.Fatalf("요청 생성 실패: %v", err)
	}

	if got := req.Header.Get("X-Amz-Security-Token"); got != "" {
		t.Errorf("세션 토큰이 없는데 헤더가 붙음: %q", got)
	}
	if strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Error("세션 토큰이 없는데 SignedHeaders에 포함됨")
	}
}

func TestPairAWSKeysPrefersSamePath(t *testing.T) {
	targets := []Target{
		{RuleID: ruleAWSAccessKeyID, Path: "app/config.py", Line: 10, Secret: "AKIA0000000000000001"},
		{RuleID: ruleAWSSecretKey, Path: "other/file.py", Line: 10, Secret: "wrong-file"},
		{RuleID: ruleAWSSecretKey, Path: "app/config.py", Line: 40, Secret: "far"},
		{RuleID: ruleAWSSecretKeyBare, Path: "app/config.py", Line: 11, Secret: "near"},
	}

	pairs := pairAWSKeys(targets)
	if got := pairs[0].secret; got != "near" {
		t.Errorf("같은 파일의 가장 가까운 줄을 골라야 한다: got %q, want %q", got, "near")
	}
}

// 같은 파일에 후보가 없으면 레포 전체에서 찾는다.
// AKIA는 README에, secret은 .env에 있는 배치가 실제로 흔하다.
func TestPairAWSKeysFallsBackAcrossFiles(t *testing.T) {
	targets := []Target{
		{RuleID: ruleAWSAccessKeyID, Path: "README.md", Line: 3, Secret: "AKIA0000000000000001"},
		{RuleID: ruleAWSSecretKey, Path: ".env", Line: 2, Secret: "elsewhere"},
	}

	if got := pairAWSKeys(targets)[0].secret; got != "elsewhere" {
		t.Errorf("다른 파일의 후보를 써야 한다: got %q", got)
	}
}

func TestPairAWSKeysNoCandidates(t *testing.T) {
	targets := []Target{
		{RuleID: ruleAWSAccessKeyID, Path: "a.py", Line: 1, Secret: "AKIA0000000000000001"},
	}

	if _, ok := pairAWSKeys(targets)[0]; ok {
		t.Error("짝이 없으면 항목이 없어야 한다")
	}

	// 짝이 없으면 요청을 만들지 않고 이유를 남긴다.
	_, reason, ok := buildCredential(targets[0], awsPairing{})
	if ok {
		t.Fatal("짝 없이 자격증명을 만들면 안 된다")
	}
	if reason == "" {
		t.Error("이유가 비어 있으면 리포트에서 원인을 알 수 없다")
	}
}

// ASIA 키는 세션 토큰 없이 검증하면 살아있어도 InvalidClientTokenId 가 나온다.
// 그 응답을 "폐기됨"으로 보고하면 진짜 유출을 안전하다고 말하는 셈이라, 세션 토큰을
// 못 찾은 동안은 시도 자체를 막는다.
func TestTemporaryAWSKeyWithoutSessionTokenIsNotValidated(t *testing.T) {
	target := Target{RuleID: ruleAWSAccessKeyID, Path: "a.py", Secret: "ASIA0000000000000001"}

	_, reason, ok := buildCredential(target, awsPairing{secret: "paired-secret"})
	if ok {
		t.Fatal("세션 토큰 없이는 검증을 시도하지 않아야 한다")
	}
	if !strings.Contains(reason, "세션 토큰") {
		t.Errorf("이유에 원인이 드러나야 한다: %q", reason)
	}
}

// 근처에서 Secret Access Key와 세션 토큰을 모두 찾으면 임시 자격증명도 검증을 시도해야 한다
// — 셋이 함께 유출되는(예: .env 파일에 세 값이 나란히 있는) 경우가 실제로 있다.
func TestTemporaryAWSKeyWithSessionTokenIsValidated(t *testing.T) {
	target := Target{RuleID: ruleAWSAccessKeyID, Path: "a.py", Secret: "ASIA0000000000000001"}

	cred, _, ok := buildCredential(target, awsPairing{secret: "paired-secret", sessionToken: "paired-token"})
	if !ok {
		t.Fatal("Secret과 세션 토큰이 모두 있으면 검증을 시도해야 한다")
	}
	if cred.sessionToken != "paired-token" {
		t.Errorf("credential에 세션 토큰이 실려야 한다: got %q", cred.sessionToken)
	}
}

// 세 값이 근처에 함께 있으면 pairAWSKeys가 세션 토큰까지 찾아야 한다.
func TestPairAWSKeysFindsNearbySessionToken(t *testing.T) {
	targets := []Target{
		{RuleID: ruleAWSAccessKeyID, Path: ".env", Line: 1, Secret: "ASIA0000000000000001"},
		{RuleID: ruleAWSSecretKey, Path: ".env", Line: 2, Secret: "paired-secret"},
		{RuleID: ruleAWSSessionToken, Path: ".env", Line: 3, Secret: "paired-token"},
	}

	got := pairAWSKeys(targets)[0]
	if got.secret != "paired-secret" {
		t.Errorf("secret = %q, want %q", got.secret, "paired-secret")
	}
	if got.sessionToken != "paired-token" {
		t.Errorf("sessionToken = %q, want %q", got.sessionToken, "paired-token")
	}
}

// 장기 자격증명(AKIA)은 세션 토큰이 근처에 있어도 무시해야 한다 — 애초에 필요하지 않다.
func TestPairAWSKeysIgnoresSessionTokenForLongTermKey(t *testing.T) {
	targets := []Target{
		{RuleID: ruleAWSAccessKeyID, Path: ".env", Line: 1, Secret: "AKIA0000000000000001"},
		{RuleID: ruleAWSSecretKey, Path: ".env", Line: 2, Secret: "paired-secret"},
		{RuleID: ruleAWSSessionToken, Path: ".env", Line: 3, Secret: "unrelated-token"},
	}

	got := pairAWSKeys(targets)[0]
	if got.sessionToken != "" {
		t.Errorf("장기 자격증명에는 세션 토큰이 붙으면 안 된다: got %q", got.sessionToken)
	}
}

func TestInspectAWS(t *testing.T) {
	body := func(code string) []byte {
		return []byte(`<ErrorResponse><Error><Code>` + code + `</Code></Error></ErrorResponse>`)
	}

	tests := []struct {
		name string
		code int
		body []byte
		want Status
	}{
		{"성공", 200, []byte(`<GetCallerIdentityResponse/>`), StatusValid},
		{"없는 키", 403, body("InvalidClientTokenId"), StatusRevoked},
		{"만료된 임시 자격증명", 403, body("ExpiredToken"), StatusRevoked},
		// 짝을 잘못 지었을 뿐 키는 살아있을 수 있다. 폐기로 단정하면 안 된다.
		{"서명 불일치", 403, body("SignatureDoesNotMatch"), StatusUnknown},
		// 인증 자체는 통과했다는 뜻이다.
		{"조직 정책 거부", 403, body("AccessDenied"), StatusValid},
		{"서버 오류", 500, nil, StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := inspectAWS(tt.code, tt.body)
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}
