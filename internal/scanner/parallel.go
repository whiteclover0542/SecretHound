package scanner

import (
	"runtime"
	"sync"

	"github.com/whiteclover0542/secrethound/internal/detector"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

// 룰 매칭(정규식 실행)이 이 파이프라인에서 유일하게 무거운 CPU 작업이다.
// 파일 I/O와 git log 파싱은 원래도 빠르고(실측: express 5,678커밋 1.4초),
// 무엇보다 git log 출력을 순서대로 해석해야 하는 상태 기반 파싱이라 병렬화하면
// 정확성을 해칠 위험이 크다. 그래서 수집·파싱은 지금처럼 한 goroutine이 순서대로
// 하고, 그 결과로 나온 "파일 하나" 또는 "히스토리 한 줄" 단위의 정규식 매칭만
// 워커 풀에 맡긴다.
//
// *regexp.Regexp와 Detector는 상태를 갖지 않아(Go 표준 라이브러리 문서상
// Regexp는 동시 사용에 안전하다) 각 잡을 잠금 없이 병렬로 처리할 수 있다.
// 결과를 모으는 부분만 채널 하나로 직렬화해 데이터 경합을 피한다.

type scanJob struct {
	loc     detector.Location
	content []byte
	line    string
	lineNo  int
	isLine  bool
}

func (j scanJob) run(det *detector.Detector) []finding.Finding {
	if j.isLine {
		return det.ScanLine(j.loc, j.line, j.lineNo)
	}
	return det.Scan(j.loc, j.content)
}

// jobRunner는 정규식 매칭을 워커 풀에 분산시키고 결과를 순서 없이 모은다.
// 잡을 넣는 쪽(수집·히스토리 파싱)은 지금처럼 한 goroutine에서 순서대로 실행되고,
// jobRunner가 그 결과만 병렬로 처리한다.
type jobRunner struct {
	det     *detector.Detector
	jobs    chan scanJob
	results chan []finding.Finding
	wg      sync.WaitGroup

	findings []finding.Finding
	done     chan struct{}
}

// jobBufferSize는 workers 수와 무관하게 넉넉히 잡는다.
// 히스토리 스캔은 추가된 줄 하나하나가 잡이 되므로 대형 레포에서 수만~수십만
// 건에 이른다(예: express 5,678커밋 → 115,806줄). 버퍼가 workers 수에 비례해
// 작으면(예: workers=1일 때 4) producer/consumer가 매번 서로를 깨워야 해서
// goroutine 스케줄링 오버헤드가 채널 자체의 처리량보다 커진다 — 실측에서
// workers=1이 병렬화 이전 순차 구현보다 오히려 느려지는 원인이었다.
const jobBufferSize = 4096

func newJobRunner(det *detector.Detector, workers int) *jobRunner {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	r := &jobRunner{
		det:     det,
		jobs:    make(chan scanJob, jobBufferSize),
		results: make(chan []finding.Finding, jobBufferSize),
		done:    make(chan struct{}),
	}

	r.wg.Add(workers)
	for range workers {
		go func() {
			defer r.wg.Done()
			for j := range r.jobs {
				if fs := j.run(r.det); len(fs) > 0 {
					r.results <- fs
				}
			}
		}()
	}

	// 워커가 전부 끝나야 results를 닫을 수 있고, results를 다 비운 뒤에야
	// findings 슬라이스가 최종 상태가 된다. 두 단계를 별도 goroutine으로 나눠
	// 잠금 없이 순서를 보장한다.
	go func() {
		r.wg.Wait()
		close(r.results)
	}()
	go func() {
		for fs := range r.results {
			r.findings = append(r.findings, fs...)
		}
		close(r.done)
	}()

	return r
}

func (r *jobRunner) submit(j scanJob) {
	r.jobs <- j
}

// finish는 더 이상 잡이 없음을 알리고, 모든 워커와 결과 수집이 끝날 때까지 기다린 뒤
// 모은 결과를 반환한다.
func (r *jobRunner) finish() []finding.Finding {
	close(r.jobs)
	<-r.done
	return r.findings
}
