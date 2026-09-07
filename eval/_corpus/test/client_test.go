package client

import "testing"

func TestAuthHeader(t *testing.T) {
	// 테스트용 더미 토큰. 실제로 유효하지 않다.
	token := "ghp_0000000000000000000000000000000000"
	if got := authHeader(token); got != "Bearer "+token {
		t.Errorf("authHeader = %q", got)
	}
}

func TestParseKey(t *testing.T) {
	fake := "AKIAEXAMPLEKEYFORTEST"
	if !isAccessKey(fake) {
		t.Error("형식 판별 실패")
	}
}
