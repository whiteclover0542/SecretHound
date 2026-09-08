// Package baseline은 "이미 알고 있는 시크릿"과 "새로 생긴 시크릿"을 구분한다.
//
// 시크릿이 이미 많은 레포에 도입하면 첫 스캔에서 수십~수백 건이 쏟아진다.
// 그 뒤로도 계속 그 상태면 CI가 영원히 빨간불이라 아무도 안 보게 된다.
// baseline은 "지금 보이는 것들은 이미 알고 있다"고 한 번 선언해두고,
// 이후 스캔에서는 거기 없던 것만 새로 보고하게 한다.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/whiteclover0542/secrethound/internal/finding"
)

// CurrentVersion이 바뀌면 이전 baseline 파일과 호환되지 않는다는 뜻이다.
const CurrentVersion = 1

type Entry struct {
	Path   string `json:"path"`
	RuleID string `json:"rule_id"`
	Hash   string `json:"hash"`
}

type Baseline struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Fingerprint는 라인 번호가 바뀌어도 흔들리지 않는 식별자다.
// 파일을 편집해 위쪽 줄이 밀리거나, 히스토리에 새 커밋이 쌓여도 같은 시크릿은
// 같은 지문을 갖는다. 파일 경로가 다르면 지문도 다르다 — 같은 값이 여러 파일에
// 있으면 각각 별도로 추적해야 전부 지웠는지 확인할 수 있기 때문이다.
//
// 원본 시크릿 값은 저장하지 않고 해시만 남긴다. baseline은 저장소에 커밋되는
// 파일이라, 원본을 넣으면 그 자체가 새로운 유출 경로가 된다.
func Fingerprint(f finding.Finding) string {
	h := sha256.Sum256([]byte(f.Path + "\x00" + f.RuleID + "\x00" + f.Secret))
	return hex.EncodeToString(h[:])
}

// From은 현재 탐지 결과를 baseline으로 만든다.
func From(findings []finding.Finding) *Baseline {
	seen := make(map[string]bool, len(findings))
	b := &Baseline{Version: CurrentVersion}

	for _, f := range findings {
		fp := Fingerprint(f)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		b.Entries = append(b.Entries, Entry{Path: f.Path, RuleID: f.RuleID, Hash: fp})
	}

	// 체크인되는 파일이므로 diff가 안정적이도록 정렬해서 저장한다.
	sort.Slice(b.Entries, func(i, j int) bool {
		if b.Entries[i].Path != b.Entries[j].Path {
			return b.Entries[i].Path < b.Entries[j].Path
		}
		if b.Entries[i].RuleID != b.Entries[j].RuleID {
			return b.Entries[i].RuleID < b.Entries[j].RuleID
		}
		return b.Entries[i].Hash < b.Entries[j].Hash
	})
	return b
}

func Save(path string, findings []finding.Finding) error {
	data, err := json.MarshalIndent(From(findings), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline 파일 읽기 실패: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("baseline 파일 파싱 실패: %w", err)
	}
	if b.Version != CurrentVersion {
		return nil, fmt.Errorf("지원하지 않는 baseline 버전: %d (현재 %d)", b.Version, CurrentVersion)
	}
	return &b, nil
}

func (b *Baseline) set() map[string]bool {
	set := make(map[string]bool, len(b.Entries))
	for _, e := range b.Entries {
		set[e.Hash] = true
	}
	return set
}

// Split은 findings를 baseline에 없는 새 것과 이미 알려진 것으로 나눈다.
// known은 새 것에서 제외된 개수다 — 리포트에 "몇 건을 baseline으로 걸렀는지" 보여주는 데 쓴다.
func Split(b *Baseline, findings []finding.Finding) (newOnes []finding.Finding, known int) {
	set := b.set()
	newOnes = make([]finding.Finding, 0, len(findings))

	for _, f := range findings {
		if set[Fingerprint(f)] {
			known++
			continue
		}
		newOnes = append(newOnes, f)
	}
	return newOnes, known
}
