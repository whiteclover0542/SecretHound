package validator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS만 검증 방식이 다르다. 다른 발급처는 토큰 하나를 헤더에 넣으면 끝이지만
// AWS는 Access Key ID와 Secret Access Key로 요청에 **서명**해야 한다.
// 즉 두 값이 짝지어져야 검증이 가능하고, 이 둘은 보통 서로 다른 줄·다른 파일에서 발견된다.

const (
	ruleAWSAccessKeyID   = "aws-access-key-id"
	ruleAWSSecretKey     = "aws-secret-access-key"
	ruleAWSSecretKeyBare = "aws-secret-access-key-bare"
	ruleAWSSessionToken  = "aws-session-token"
)

// awsPairing은 Access Key ID 하나에 짝지어진 나머지 조각들이다.
// sessionToken은 임시 자격증명(ASIA)일 때만 채워진다.
type awsPairing struct {
	secret       string
	sessionToken string
}

const (
	awsRegion    = "us-east-1"
	awsService   = "sts"
	awsAlgorithm = "AWS4-HMAC-SHA256"
)

// GetCallerIdentity는 IAM 권한이 전혀 필요 없고 아무것도 바꾸지 않는다.
// "이 자격증명이 누구인가"만 답한다. 살아있는지 확인하기에 이보다 안전한 호출이 없다.
const (
	stsPayload     = "Action=GetCallerIdentity&Version=2011-06-15"
	stsContentType = "application/x-www-form-urlencoded; charset=utf-8"
)

// pairAWSKeys는 Access Key ID 대상마다 짝이 될 Secret Access Key를(그리고 임시
// 자격증명이면 세션 토큰까지) 찾는다. 반환하는 맵의 키는 targets 슬라이스의 인덱스다.
//
// 같은 파일에 있는 후보를 줄 거리가 가까운 순으로 먼저 고르고, 없으면 레포 전체에서 찾는다.
// (AKIA는 README에, secret은 .env에 있는 식으로 흩어지는 경우가 흔하다)
//
// 한계: 후보를 하나만 고른다. 한 레포에 AWS 자격증명 쌍이 여럿 있고 같은 파일에도
// 없으면 잘못 짝지을 수 있다. 그 경우 STS가 SignatureDoesNotMatch를 돌려주므로
// "폐기됨"이 아니라 "검증불가"로 보고된다 — 틀린 짝 때문에 살아있는 키를
// 죽었다고 보고하는 일은 생기지 않는다.
func pairAWSKeys(targets []Target) map[int]awsPairing {
	var secretCandidates, tokenCandidates []int
	for i := range targets {
		switch targets[i].RuleID {
		case ruleAWSSecretKey, ruleAWSSecretKeyBare:
			if targets[i].Secret != "" {
				secretCandidates = append(secretCandidates, i)
			}
		case ruleAWSSessionToken:
			if targets[i].Secret != "" {
				tokenCandidates = append(tokenCandidates, i)
			}
		}
	}
	if len(secretCandidates) == 0 {
		return nil
	}

	pairs := make(map[int]awsPairing)
	for i := range targets {
		if targets[i].RuleID != ruleAWSAccessKeyID {
			continue
		}
		p := awsPairing{secret: nearestValue(targets, i, secretCandidates)}
		if isTemporaryAWSKey(targets[i].Secret) && len(tokenCandidates) > 0 {
			p.sessionToken = nearestValue(targets, i, tokenCandidates)
		}
		pairs[i] = p
	}
	return pairs
}

// nearestValue는 candidates 중 idx와 같은 파일에 있고 줄 거리가 가장 가까운 것의
// 값을 돌려준다. 같은 파일에 후보가 없으면 레포 전체에서 가장 가까운 것을 쓴다.
// secret과 session token 페어링 모두 이 로직을 그대로 쓴다 — 둘 다 "같은 자격증명
// 조각끼리는 물리적으로 가까이 있을 가능성이 높다"는 같은 휴리스틱이다.
func nearestValue(targets []Target, idx int, candidates []int) string {
	akid := targets[idx]

	pool := make([]int, 0, len(candidates))
	for _, c := range candidates {
		if targets[c].Path == akid.Path {
			pool = append(pool, c)
		}
	}
	if len(pool) == 0 {
		pool = append(pool, candidates...)
	}

	sort.SliceStable(pool, func(a, b int) bool {
		return distance(targets[pool[a]].Line, akid.Line) < distance(targets[pool[b]].Line, akid.Line)
	})
	return targets[pool[0]].Secret
}

func distance(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

// isTemporaryAWSKey는 STS가 발급한 임시 자격증명인지 판별한다.
// ASIA로 시작하는 키는 세션 토큰까지 있어야 인증된다. 세션 토큰은 보통 같이
// 커밋되지 않으므로(pairAWSKeys가 못 찾으면) 검증을 시도하지 않고 검증불가로
// 남긴다 — 세션 토큰 없이 서명하면 살아있는 키도 InvalidClientTokenId가 나와
// "폐기됨"으로 잘못 보고되기 때문이다. 근처에서 세션 토큰까지 찾은 경우에만
// (예: .env 파일에 세 값이 함께 있는 경우) buildCredential이 실제로 검증을 시도한다.
func isTemporaryAWSKey(id string) bool {
	return strings.HasPrefix(id, "ASIA")
}

func buildAWSRequest(ctx context.Context, base string, cred credential) (*http.Request, error) {
	endpoint := strings.TrimSuffix(base, "/") + "/"

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(stsPayload))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("Content-Type", stsContentType)
	req.Header.Set("X-Amz-Date", amzDate)

	headers := []sigv4Header{
		{"content-type", stsContentType},
		{"host", u.Host},
		{"x-amz-date", amzDate},
	}
	// 임시 자격증명(ASIA)은 세션 토큰도 요청에 실어야 인증된다. botocore를 포함해
	// AWS의 참조 구현들이 이 헤더를 서명 대상(SignedHeaders)에 포함시키므로 그대로 따른다
	// — 일부 문서는 서비스에 따라 서명 없이 덧붙이기만 해도 된다고 하지만, 서명이
	// 틀리면 살아있는 키도 SignatureDoesNotMatch로 조용히 "검증불가" 처리되므로
	// 검증된 쪽(서명 포함)을 택한다.
	if cred.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", cred.sessionToken)
		headers = append(headers, sigv4Header{"x-amz-security-token", cred.sessionToken})
	}

	sig := signV4(cred.secret, sigv4Input{
		method:  http.MethodPost,
		uri:     "/",
		payload: []byte(stsPayload),
		region:  awsRegion,
		service: awsService,
		now:     now,
		headers: headers,
	})

	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		awsAlgorithm, cred.id, sig.scope, sig.signedHeaders, sig.signature))
	return req, nil
}

type sigv4Header struct {
	name  string // 소문자여야 한다
	value string
}

// sigv4Input은 서명 대상 요청을 표현한다.
// headers는 이름 순으로 정렬돼 있지 않아도 되며 signV4가 정렬한다.
type sigv4Input struct {
	method  string
	uri     string
	query   string
	headers []sigv4Header
	payload []byte
	region  string
	service string
	now     time.Time
}

type sigv4Result struct {
	signature     string
	scope         string
	signedHeaders string
}

// signV4는 AWS Signature Version 4 서명을 계산한다.
//
// SDK를 쓰지 않고 직접 구현한 이유는, 이 한 번의 호출을 위해 aws-sdk-go-v2 전체를
// 의존성으로 끌어오면 단일 실행 바이너리라는 도구의 전제가 무너지기 때문이다.
// 서명에 필요한 것은 표준 라이브러리의 hmac/sha256뿐이다.
//
// STS 호출과 분리해 둔 덕분에 AWS가 공개한 SigV4 테스트 벡터로 직접 검증할 수 있다.
// 서명이 틀리면 살아있는 키가 SignatureDoesNotMatch를 받아 전부 "검증불가"가 되므로,
// 조용히 무용지물이 되는 것을 막으려면 이 검증이 꼭 필요하다.
func signV4(secretKey string, in sigv4Input) sigv4Result {
	headers := append([]sigv4Header(nil), in.headers...)
	sort.Slice(headers, func(i, j int) bool { return headers[i].name < headers[j].name })

	var canonicalHeaders strings.Builder
	names := make([]string, 0, len(headers))
	for _, h := range headers {
		canonicalHeaders.WriteString(h.name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(h.value))
		canonicalHeaders.WriteByte('\n')
		names = append(names, h.name)
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{
		in.method,
		in.uri,
		in.query,
		canonicalHeaders.String(),
		signedHeaders,
		hexSHA256(in.payload),
	}, "\n")

	amzDate := in.now.UTC().Format("20060102T150405Z")
	dateStamp := in.now.UTC().Format("20060102")
	scope := strings.Join([]string{dateStamp, in.region, in.service, "aws4_request"}, "/")

	stringToSign := strings.Join([]string{
		awsAlgorithm,
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	key := []byte("AWS4" + secretKey)
	for _, part := range []string{dateStamp, in.region, in.service, "aws4_request"} {
		key = hmacSHA256(key, part)
	}

	return sigv4Result{
		signature:     hex.EncodeToString(hmacSHA256(key, stringToSign)),
		scope:         scope,
		signedHeaders: signedHeaders,
	}
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// inspectAWS는 STS의 오류 코드를 상태로 옮긴다.
// AWS는 "그런 키는 없다"와 "서명이 틀렸다"를 구분해서 알려주는데, 이 차이가 중요하다.
func inspectAWS(code int, body []byte) (Status, string) {
	if code >= 200 && code < 300 {
		return StatusValid, ""
	}
	if code != http.StatusForbidden {
		return classifyWith(nil, code, body)
	}

	var payload struct {
		Code string `xml:"Error>Code"`
	}
	if err := xml.Unmarshal(body, &payload); err != nil {
		return StatusUnknown, "STS 응답을 해석할 수 없음"
	}

	switch payload.Code {
	case "InvalidClientTokenId":
		return StatusRevoked, "STS가 모르는 Access Key ID"
	case "ExpiredToken", "TokenRefreshRequired":
		return StatusRevoked, "만료된 임시 자격증명"
	case "SignatureDoesNotMatch":
		// Access Key ID 자체는 AWS에 실재한다는 뜻이다. 짝지은 Secret이 틀렸을 뿐이라
		// 이 키가 죽었다고 말할 수 없다. 오히려 살아있을 가능성이 높다.
		return StatusUnknown, "Access Key ID는 실재하나 짝지은 Secret Access Key가 맞지 않음"
	case "AccessDenied":
		// GetCallerIdentity는 권한이 필요 없다. 거부됐다면 SCP 등 조직 정책 때문이며
		// 인증 자체는 통과했다는 뜻이다.
		return StatusValid, "인증은 통과했으나 조직 정책이 호출을 거부함"
	}
	return StatusUnknown, "STS 오류: " + payload.Code
}
