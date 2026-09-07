package scanner

import (
	"context"
	"time"

	"github.com/whiteclover0542/secrethound/internal/collector"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/detector"
	"github.com/whiteclover0542/secrethound/internal/filter"
	"github.com/whiteclover0542/secrethound/internal/finding"
	"github.com/whiteclover0542/secrethound/internal/validator"
)

// 수집 → 탐지 → 오탐 필터로 이어지는 스캔 파이프라인.
// CLI와 평가 하네스가 같은 경로를 쓰도록 여기 한 곳에만 둔다.
// (하네스가 파이프라인을 따로 구현하면 실제 제품이 아닌 다른 것을 측정하게 된다)

type Options struct {
	Target     string
	History    bool
	MaxCommits int
	Validate   ValidateOptions
}

// ValidateOptions는 탐지된 키를 발급처에 확인하는 단계를 제어한다.
// 자격증명을 외부로 내보내는 동작이라 Enabled의 기본값 false를 유지하는 것이 중요하다.
type ValidateOptions struct {
	Enabled bool
	Timeout time.Duration
}

type Result struct {
	Findings       []finding.Finding
	FilesScanned   int
	FilesSkipped   int
	CommitsScanned int
	FilteredOut    int

	// Validated는 검증 단계를 실제로 돌렸는지를 뜻한다.
	// 리포트가 "검증 안 함"과 "전부 검증불가"를 구분해 표시하기 위해 필요하다.
	Validated  bool
	Validation validator.Stats
}

func Run(ctx context.Context, rs *config.Ruleset, opts Options) (Result, error) {
	var result Result

	det := detector.New(rs.Rules)
	col := collector.New(&rs.Filter)
	var findings []finding.Finding

	stats, err := col.WalkTree(opts.Target, func(s collector.Source) error {
		findings = append(findings, det.Scan(detector.Location{Path: s.Path}, s.Content)...)
		return nil
	})
	if err != nil {
		return result, err
	}
	result.FilesScanned = stats.Scanned
	result.FilesSkipped = stats.Skipped

	if opts.History {
		histStats, err := col.WalkHistory(opts.Target,
			collector.HistoryOptions{MaxCommits: opts.MaxCommits},
			func(ch collector.Change) error {
				loc := detector.Location{
					Path:   ch.Path,
					Commit: ch.Commit,
					Author: ch.Author,
					Date:   ch.Date,
				}
				findings = append(findings, det.ScanLine(loc, ch.Line, ch.LineNo)...)
				return nil
			})
		if err != nil {
			return result, err
		}
		result.CommitsScanned = histStats.Commits
	}

	fp, err := filter.New(&rs.Filter)
	if err != nil {
		return result, err
	}

	kept, fpStats := fp.Apply(findings)

	// Dedupe: 한 위치에 여러 룰이 걸린 경우를 정리한다.
	// GroupBySecret: 같은 값이 여러 커밋·줄에 흩어진 경우를 최초 유입 하나로 묶는다.
	result.Findings = filter.GroupBySecret(filter.Dedupe(kept))
	result.FilteredOut = fpStats.Filtered + fpStats.Allowlist

	// 검증은 오탐 필터를 통과한 것만 대상으로 한다.
	// 걸러낸 후보까지 발급처에 물어보면 네트워크 호출이 몇 배로 늘고,
	// 무엇보다 리포트에 나오지도 않을 값을 외부로 내보내게 된다.
	if opts.Validate.Enabled {
		result.Validation = validateFindings(ctx, result.Findings, opts.Validate)
		result.Validated = true
	}

	return result, nil
}

func validateFindings(ctx context.Context, findings []finding.Finding, opts ValidateOptions) validator.Stats {
	targets := make([]validator.Target, len(findings))
	for i, f := range findings {
		targets[i] = validator.Target{
			RuleID: f.RuleID,
			Path:   f.Path,
			Line:   f.Line,
			Secret: f.Secret,
		}
	}

	results, stats := validator.New(validator.Options{Timeout: opts.Timeout}).Run(ctx, targets)
	for i := range findings {
		findings[i].Validation = results[i]
	}
	return stats
}
