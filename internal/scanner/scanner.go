package scanner

import (
	"github.com/whiteclover0542/secrethound/internal/collector"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/detector"
	"github.com/whiteclover0542/secrethound/internal/filter"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

// 수집 → 탐지 → 오탐 필터로 이어지는 스캔 파이프라인.
// CLI와 평가 하네스가 같은 경로를 쓰도록 여기 한 곳에만 둔다.
// (하네스가 파이프라인을 따로 구현하면 실제 제품이 아닌 다른 것을 측정하게 된다)

type Options struct {
	Target     string
	History    bool
	MaxCommits int
}

type Result struct {
	Findings       []finding.Finding
	FilesScanned   int
	FilesSkipped   int
	CommitsScanned int
	FilteredOut    int
}

func Run(rs *config.Ruleset, opts Options) (Result, error) {
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

	return result, nil
}
