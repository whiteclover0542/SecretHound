// Package validator는 탐지된 자격증명이 지금도 살아있는지 발급처 API에 물어본다.
//
// FP Filter의 감점 규칙이 "이건 시크릿처럼 안 보인다"는 휴리스틱 추정인 것과 달리,
// 발급처의 응답은 추정이 아니다. 다만 그 응답이 무엇을 증명하는지는 상태마다 다르다.
//
//	유효(valid)     — 발급처가 인증에 성공했다. 이 값은 실재하는 살아있는 키다.
//	                  탐지가 맞았다는 것과 지금 위험하다는 것을 동시에 증명한다.
//	폐기됨(revoked) — 발급처가 인증을 거부했다. **탐지가 틀렸다는 뜻이 아니다.**
//	                  폐기된 진짜 키와 애초에 키가 아니었던 문자열은 응답이 같아서
//	                  이 둘을 구분할 수 없다. 증명되는 것은 "지금은 악용 불가"뿐이다.
//	검증불가        — 네트워크 없음, 레이트리밋, 검증기 미지원 등. 판단 보류다.
//
// 그래서 검증 결과로 탐지 결과를 지우지 않고, 신뢰도(Confidence)도 건드리지 않는다.
// 신뢰도는 "탐지가 맞았는가", 검증은 "지금 위험한가"라는 서로 다른 축이고,
// 하나로 합치면 폐기된 진짜 유출이 리포트에서 사라진다. 히스토리에 남은 폐기 키는
// 여전히 "이 레포는 시크릿을 커밋한 적이 있다"는 사실을 말해주므로 보고 대상이다.
//
// # 설계 제약
//
// 찾아낸 자격증명을 외부로 내보내는 기능이라 다음을 지킨다.
//
//  1. 기본 비활성. CLI의 --validate 로만 켜진다.
//  2. 부작용 없는 최소 권한 엔드포인트만 호출한다(신원 조회 등 읽기 전용).
//     상태를 바꾸거나 메시지를 보내는 엔드포인트는 쓰지 않는다.
//  3. 키 값은 로그·리포트 어디에도 남기지 않는다. 토큰을 URL에 담는 API(Telegram)가
//     있어 에러 문자열에 값이 섞여 나오므로, 기록 직전에 redact 로 지운다.
//  4. 네트워크가 없으면 조용히 "검증불가"로 남기고 스캔 결과는 그대로 낸다.
//     검증 실패가 탐지 리포트를 망가뜨리는 일은 없어야 한다.
package validator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Target은 검증 대상 하나다. Finding 전체가 아니라 검증에 필요한 필드만 받는다.
//
// finding 패키지가 Result를 자기 필드로 갖기 때문에 여기서 finding을 참조하면
// import 순환이 된다. 그 제약이 오히려 경계를 분명히 해준다 —
// 검증기는 탐지 결과의 나머지(심각도·커밋·신뢰도)를 알 필요가 없다.
type Target struct {
	RuleID string
	Path   string
	Line   int
	Secret string
}

// Status는 검증 결과 3단계다. JSON 스키마의 일부이므로 값을 바꾸면 호환이 깨진다.
type Status string

const (
	StatusValid   Status = "valid"
	StatusRevoked Status = "revoked"
	StatusUnknown Status = "unknown"
)

// Result는 Finding에 붙는 검증 결과다.
// Reason에는 어떤 경우에도 키 값이 들어가면 안 된다(redact 참조).
type Result struct {
	Status   Status `json:"status"`
	Provider string `json:"provider,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type Stats struct {
	Checked     int  // 실제로 네트워크 검증을 시도한 finding 수
	Valid       int  // 살아있는 키
	Revoked     int  // 발급처가 거부한 값
	Unknown     int  // 판단 보류
	Unsupported int  // 검증기가 없는 룰이라 시도조차 하지 않은 finding 수
	Offline     bool // 연속 네트워크 실패로 남은 검증을 포기했는지
}

type Options struct {
	// Timeout은 요청 하나당 제한 시간이다.
	Timeout time.Duration
	// Workers는 동시 요청 수. 발급처에 부담을 주지 않도록 작게 유지한다.
	Workers int
}

const (
	defaultTimeout = 5 * time.Second
	defaultWorkers = 4

	// 연속으로 이만큼 네트워크 오류가 나면 오프라인으로 보고 남은 검증을 건너뛴다.
	// 인터넷이 없는 CI에서 finding 수만큼 타임아웃을 기다리는 것을 막는다.
	offlineThreshold = 3

	// 응답 본문은 상태 판별에만 쓰므로 앞부분만 읽는다.
	maxBodyBytes = 8 << 10

	userAgent = "secrethound-validator"
)

type Validator struct {
	client    *http.Client
	endpoints endpoints
	workers   int

	mu       sync.Mutex
	netFails int
	offline  bool
}

func New(opts Options) *Validator {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	return &Validator{
		client: &http.Client{
			Timeout: opts.Timeout,
			// 리다이렉트를 따라가면 Authorization 헤더가 의도하지 않은 호스트로
			// 전달될 수 있다. 검증 대상 API는 모두 리다이렉트하지 않으므로 막는다.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoints: defaultEndpoints(),
		workers:   opts.Workers,
	}
}

// job은 검증 요청 하나다. 같은 값이 여러 곳에서 발견되면
// 호출은 한 번만 하고 결과를 모든 대상에 나눠 붙인다.
type job struct {
	provider string
	cred     credential
	targets  []int // targets 슬라이스 내 인덱스
}

// Run은 targets와 같은 길이의 결과 슬라이스를 돌려준다.
// 검증기가 없는 대상의 자리는 nil이다 — "검증 안 함"과 "검증했으나 판단 불가"는 다른 상태다.
func (v *Validator) Run(ctx context.Context, targets []Target) ([]*Result, Stats) {
	var stats Stats

	out := make([]*Result, len(targets))
	pairs := pairAWSKeys(targets)

	jobs := make([]*job, 0, len(targets))
	index := make(map[string]*job, len(targets))

	for i := range targets {
		name, ok := providerFor(targets[i].RuleID)
		if !ok {
			stats.Unsupported++
			continue
		}

		cred, reason, ok := buildCredential(targets[i], pairs[i])
		if !ok {
			// 룰에는 검증기가 있지만 이 대상만으로는 요청을 만들 수 없다.
			// 네트워크를 쓰지 않았으므로 Checked에는 세지 않는다.
			out[i] = &Result{
				Status:   StatusUnknown,
				Provider: providers[name].label,
				Reason:   reason,
			}
			stats.Unknown++
			continue
		}

		// 같은 값이 여러 곳에서 발견되면 호출은 한 번만 하고 결과를 나눠 붙인다.
		key := name + "\x00" + cred.id + "\x00" + cred.secret
		if j, seen := index[key]; seen {
			j.targets = append(j.targets, i)
			continue
		}
		j := &job{provider: name, cred: cred, targets: []int{i}}
		index[key] = j
		jobs = append(jobs, j)
	}

	results := v.runJobs(ctx, jobs)

	for i, j := range jobs {
		for _, t := range j.targets {
			r := results[i]
			out[t] = &r
			stats.Checked++
			switch r.Status {
			case StatusValid:
				stats.Valid++
			case StatusRevoked:
				stats.Revoked++
			default:
				stats.Unknown++
			}
		}
	}

	stats.Offline = v.isOffline()
	return out, stats
}

func (v *Validator) runJobs(ctx context.Context, jobs []*job) []Result {
	// 스캔이 중간에 취소되면 아직 처리하지 못한 자리가 남는다.
	// 빈 Status가 리포트에 그대로 나가면 JSON 스키마가 깨지므로 미리 채워 둔다.
	results := make([]Result, len(jobs))
	for i := range results {
		results[i] = Result{
			Status:   StatusUnknown,
			Provider: providers[jobs[i].provider].label,
			Reason:   "검증이 취소됨",
		}
	}
	if len(jobs) == 0 {
		return results
	}

	workers := min(v.workers, len(jobs))
	queue := make(chan int)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range queue {
				results[i] = v.check(ctx, jobs[i])
			}
		}()
	}

	for i := range jobs {
		select {
		case queue <- i:
		case <-ctx.Done():
			close(queue)
			wg.Wait()
			return results
		}
	}
	close(queue)
	wg.Wait()

	return results
}

func (v *Validator) check(ctx context.Context, j *job) Result {
	p := providers[j.provider]
	res := Result{Provider: p.label}

	if v.isOffline() {
		res.Status = StatusUnknown
		res.Reason = "네트워크에 연결할 수 없어 검증을 건너뜀"
		return res
	}

	status, reason := v.request(ctx, p, j.cred)
	res.Status = status
	res.Reason = redact(reason, j.cred)
	return res
}

// request는 요청을 한 번 보내고, 레이트리밋이면 Retry-After 만큼 기다렸다 한 번만 재시도한다.
func (v *Validator) request(ctx context.Context, p provider, cred credential) (Status, string) {
	status, reason, wait := v.attempt(ctx, p, cred)
	if wait <= 0 {
		return status, reason
	}

	select {
	case <-time.After(wait):
	case <-ctx.Done():
		return StatusUnknown, "검증이 취소됨"
	}

	status, reason, _ = v.attempt(ctx, p, cred)
	return status, reason
}

// attempt의 세 번째 반환값은 "이만큼 기다린 뒤 재시도할 가치가 있다"는 뜻이다.
// 0이면 재시도하지 않는다.
func (v *Validator) attempt(ctx context.Context, p provider, cred credential) (Status, string, time.Duration) {
	req, err := p.build(ctx, v.endpoints[p.name], cred)
	if err != nil {
		return StatusUnknown, "검증 요청 생성 실패: " + err.Error(), 0
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := v.client.Do(req)
	if err != nil {
		if isNetworkError(err) {
			v.recordNetworkFailure()
			return StatusUnknown, "네트워크 오류로 검증 실패", 0
		}
		return StatusUnknown, "검증 요청 실패: " + err.Error(), 0
	}
	defer resp.Body.Close()

	v.recordNetworkSuccess()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	if wait, ok := retryAfter(resp); ok {
		return StatusUnknown, "레이트리밋", wait
	}

	if p.inspect != nil {
		status, reason := p.inspect(resp.StatusCode, body)
		return status, reason, 0
	}
	status, reason := classifyWith(p.revoked, resp.StatusCode, body)
	return status, reason, 0
}

// retryAfter는 레이트리밋 응답에서 대기 시간을 읽는다.
// 대기가 지나치게 길면 재시도하지 않는다. 스캔 한 번이 몇 분씩 멈추면 안 된다.
func retryAfter(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != http.StatusTooManyRequests {
		return 0, false
	}

	const maxWait = 10 * time.Second

	d, err := time.ParseDuration(strings.TrimSpace(resp.Header.Get("Retry-After")) + "s")
	if err != nil || d <= 0 || d > maxWait {
		return 0, true
	}
	return d, true
}

// classifyWith는 응답을 상태로 옮긴다.
//
// 403을 폐기로 보지 않는 것이 중요하다. GitHub는 레이트리밋과 계정 정지에도 403을 주고,
// 권한이 모자란 유효한 키도 403을 받는다. 살아있는 키를 죽었다고 보고하는 쪽이
// 판단 보류보다 훨씬 나쁜 오류라서 403은 전부 검증불가로 남긴다.
//
// sig가 있으면 **그 형태와 정확히 일치할 때만** 폐기로 판정한다.
// 상태코드는 맞는데 본문이 다르면 검증기 자체가 고장났을 가능성이 있으므로
// 폐기가 아니라 검증불가로 남긴다. 조용히 틀리는 것보다 모른다고 말하는 편이 낫다.
func classifyWith(sig *signature, code int, body []byte) (Status, string) {
	switch {
	case code >= 200 && code < 300:
		return StatusValid, ""
	case code == http.StatusTooManyRequests:
		return StatusUnknown, "레이트리밋"
	case code >= 500:
		return StatusUnknown, "발급처 서버 오류"
	}

	if sig == nil {
		// 실제 응답을 확인하지 못한 발급처. 상태코드만 보고 판정한다.
		switch code {
		case http.StatusUnauthorized:
			return StatusRevoked, "발급처가 인증을 거부함 (응답 형식 미확인)"
		case http.StatusForbidden:
			return StatusUnknown, "403 — 권한 부족·레이트리밋·계정 정지를 구분할 수 없음"
		}
		return StatusUnknown, "예상하지 못한 응답 코드"
	}

	if sig.matches(code, body) {
		return StatusRevoked, "발급처가 인증을 거부함"
	}
	return StatusUnknown, fmt.Sprintf(
		"%d 응답이지만 발급처의 인증 거부 형식과 달라 판단 보류 — 검증기 점검 필요", code)
}

func (v *Validator) recordNetworkFailure() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.netFails++
	if v.netFails >= offlineThreshold {
		v.offline = true
	}
}

func (v *Validator) recordNetworkSuccess() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.netFails = 0
}

func (v *Validator) isOffline() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.offline
}

// isNetworkError는 "연결 자체가 안 됐다"와 "서버가 응답했다"를 구분한다.
// 전자만 오프라인 판정에 쌓는다.
func isNetworkError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// redact는 기록에 남길 문자열에서 키 값을 지운다.
//
// Telegram처럼 토큰을 URL 경로에 담는 API가 있어서, Go의 *url.Error 는
// 에러 메시지에 요청 URL을 통째로 넣는다. 그대로 Reason에 담으면
// 리포트 파일이 곧 유출 경로가 된다.
func redact(s string, cred credential) string {
	const mark = "[REDACTED]"
	for _, v := range []string{cred.secret, cred.id} {
		if len(v) < 8 {
			continue
		}
		s = strings.ReplaceAll(s, v, mark)
	}
	return s
}
