package detector

import (
	"testing"

	secrethound "github.com/whiteclover0542/secrethound"
	"github.com/whiteclover0542/secrethound/internal/config"
	"github.com/whiteclover0542/secrethound/internal/finding"
)

// 실제 배포되는 룰셋으로 검증한다. 룰 수정이 탐지 동작을 깨뜨리면 여기서 잡힌다.
func newDetector(t *testing.T) *Detector {
	t.Helper()
	rs, err := config.Parse(secrethound.DefaultRuleset)
	if err != nil {
		t.Fatalf("기본 룰셋 로드 실패: %v", err)
	}
	return New(rs.Rules)
}

func ruleIDs(fs []finding.Finding) map[string]finding.Finding {
	m := make(map[string]finding.Finding, len(fs))
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

func TestScanDetectsKnownSecrets(t *testing.T) {
	content := []byte(`package config

const region = "ap-northeast-2"
const awsKey = "AKIAIOSFODNN7EXAMPLE"
token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
`)

	found := ruleIDs(newDetector(t).Scan(Location{Path: "config.go"}, content))

	aws, ok := found["aws-access-key-id"]
	if !ok {
		t.Fatal("AWS Access Key ID를 탐지하지 못함")
	}
	if aws.Line != 4 {
		t.Errorf("Line = %d, 기대값 4", aws.Line)
	}
	if aws.Secret != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Secret = %q", aws.Secret)
	}
	if aws.Masked == aws.Secret {
		t.Error("마스킹되지 않은 값이 Masked에 담김")
	}

	if _, ok := found["github-pat"]; !ok {
		t.Error("GitHub PAT를 탐지하지 못함")
	}
}

// 정규식만으로는 더미 값도 매칭되므로, 룰에 설정된 엔트로피 임계값이 실제로 걸러내는지 확인한다.
func TestScanRejectsLowEntropyValue(t *testing.T) {
	d := newDetector(t)

	dummy := []byte(`aws_secret_access_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`)
	if fs := d.Scan(Location{Path: "dummy.env"}, dummy); len(fs) != 0 {
		t.Errorf("엔트로피가 낮은 더미 값이 탐지됨: %+v", fs)
	}

	real := []byte(`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)
	if fs := d.Scan(Location{Path: "real.env"}, real); len(fs) == 0 {
		t.Error("정상적인 AWS Secret Key를 탐지하지 못함")
	}
}

func TestScanIgnoresPlainText(t *testing.T) {
	content := []byte("이 문서는 API 키를 커밋하지 말라고 안내하는 평범한 문장입니다.\nREADME 내용입니다.\n")
	if fs := newDetector(t).Scan(Location{Path: "README.md"}, content); len(fs) != 0 {
		t.Errorf("평문에서 오탐 발생: %+v", fs)
	}
}

// 히스토리 스캔은 diff에서 추출한 줄 하나를 실제 파일 줄 번호와 함께 넘긴다.
func TestScanLineCarriesCommitMetadata(t *testing.T) {
	loc := Location{Path: "app.js", Commit: "abc1234", Author: "someone", Date: "2026-01-01T00:00:00+09:00"}
	line := `const key = "ghp_9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXk";`

	fs := newDetector(t).ScanLine(loc, line, 42)
	if len(fs) != 1 {
		t.Fatalf("탐지 건수 = %d, 기대값 1", len(fs))
	}
	if fs[0].Line != 42 {
		t.Errorf("Line = %d, 기대값 42", fs[0].Line)
	}
	if fs[0].Commit != "abc1234" || fs[0].Author != "someone" {
		t.Errorf("커밋 메타데이터가 누락됨: %+v", fs[0])
	}
}

func TestShannon(t *testing.T) {
	if got := Shannon("aaaaaaaa"); got != 0 {
		t.Errorf("동일 문자 반복의 엔트로피 = %f, 기대값 0", got)
	}
	if Shannon("wJalrXUtnFEMI/K7MDENG") <= Shannon("aaaaaaaaaaaaaaaaaaaaa") {
		t.Error("무작위 문자열의 엔트로피가 반복 문자열보다 높지 않음")
	}
}

func TestMask(t *testing.T) {
	if got := Mask("short"); got != "*****" {
		t.Errorf("짧은 값 마스킹 = %q", got)
	}
	if got := Mask("ghp_1234567890abcdef"); got != "ghp_12******cdef" {
		t.Errorf("마스킹 결과 = %q", got)
	}
}
