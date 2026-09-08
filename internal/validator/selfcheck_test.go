package validator

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 모든 시그니처가 서로의 신호를 흉내 내지 않는지 확인한다.
// 예를 들어 GitHub과 GitLab이 우연히 같은 (코드, 마커)를 쓰면 한쪽 검증기의
// 응답 파싱이 뒤바뀌어도 이 방식으로는 못 잡는다. 실제 값이 다르므로 걱정할 상황은
// 아니지만, 앞으로 시그니처를 추가할 때 복붙 실수를 막는 안전장치로 둔다.
func TestSignaturesAreDistinct(t *testing.T) {
	type key struct {
		code   int
		marker string
	}
	seen := make(map[key]string)

	for name, p := range providers {
		if p.revoked == nil || len(p.revoked.markers) == 0 {
			continue
		}
		for _, m := range p.revoked.markers {
			k := key{p.revoked.code, m}
			if other, ok := seen[k]; ok {
				t.Errorf("%s와 %s가 같은 시그니처(%d, %q)를 공유함", name, other, k.code, k.marker)
			}
			seen[k] = name
		}
	}
}

// probes에 등록된 발급처와 providers에 등록된 발급처가 어긋나면
// selfcheck가 일부 발급처를 조용히 건너뛴다.
func TestProbesCoverAllProviders(t *testing.T) {
	probe := probes()
	for name := range providers {
		if _, ok := probe[name]; !ok {
			t.Errorf("%s 에 대한 셀프체크 프로브가 없음", name)
		}
	}
	for name := range probe {
		if _, ok := providers[name]; !ok {
			t.Errorf("probes에 존재하지 않는 provider %q 가 등록됨", name)
		}
	}
}

// SelfCheck가 로컬 서버를 상대로도 동작하는지, 가짜 키가 거부됐을 때 OK를
// true로 판정하는지 확인한다. 실제 API 응답 재현이 아니라 배선 확인이 목적이다.
func TestSelfCheckAgainstFakeServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	t.Cleanup(srv.Close)

	v := New(Options{Timeout: 2 * time.Second, Workers: 2})
	v.client.Transport = srv.Client().Transport
	for name := range v.endpoints {
		v.endpoints[name] = srv.URL
	}

	results := v.SelfCheck(t.Context())
	if len(results) != len(providers) {
		t.Fatalf("결과 수 = %d, 기대값 %d", len(results), len(providers))
	}

	for _, r := range results {
		if r.Provider == "github" {
			if !r.OK {
				t.Errorf("GitHub 시그니처와 일치하는 응답인데 OK가 아님: %+v", r)
			}
		}
	}
}
