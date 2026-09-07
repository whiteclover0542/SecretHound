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

func TestPairAWSKeysPrefersSamePath(t *testing.T) {
	targets := []Target{
		{RuleID: ruleAWSAccessKeyID, Path: "app/config.py", Line: 10, Secret: "AKIA0000000000000001"},
		{RuleID: ruleAWSSecretKey, Path: "other/file.py", Line: 10, Secret: "wrong-file"},
		{RuleID: ruleAWSSecretKey, Path: "app/config.py", Line: 40, Secret: "far"},
		{RuleID: ruleAWSSecretKeyBare, Path: "app/config.py", Line: 11, Secret: "near"},
	}

	pairs := pairAWSKeys(targets)
	if got := pairs[0]; got != "near" {
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

	if got := pairAWSKeys(targets)[0]; got != "elsewhere" {
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
	_, reason, ok := buildCredential(targets[0], "")
	if ok {
		t.Fatal("짝 없이 자격증명을 만들면 안 된다")
	}
	if reason == "" {
		t.Error("이유가 비어 있으면 리포트에서 원인을 알 수 없다")
	}
}

// ASIA 키는 세션 토큰 없이 검증하면 살아있어도 InvalidClientTokenId 가 나온다.
// 그 응답을 "폐기됨"으로 보고하면 진짜 유출을 안전하다고 말하는 셈이라 시도 자체를 막는다.
func TestTemporaryAWSKeyIsNotValidated(t *testing.T) {
	target := Target{RuleID: ruleAWSAccessKeyID, Path: "a.py", Secret: "ASIA0000000000000001"}

	_, reason, ok := buildCredential(target, "paired-secret")
	if ok {
		t.Fatal("임시 자격증명은 검증을 시도하지 않아야 한다")
	}
	if !strings.Contains(reason, "세션 토큰") {
		t.Errorf("이유에 원인이 드러나야 한다: %q", reason)
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
