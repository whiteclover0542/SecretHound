package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/whiteclover0542/secrethound/internal/finding"
)

// WriteMarkdown은 문서 뷰어(깃허브·노션·메모장)에서 그대로 읽히는 리포트를 쓴다.
//
// 텍스트 출력과 담는 정보는 같다. 다른 것은 독자다 — 터미널에 익숙하지 않은 사람이
// 결과 파일을 건네받아 읽는 상황을 가정해, 고정폭 정렬 대신 표를 쓰고 용어
// (심각도·신뢰도·마스킹)에 짧은 설명을 붙인다.
func WriteMarkdown(w io.Writer, r Report) error {
	fmt.Fprintln(w, "# secrethound 검사 결과")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- **검사한 곳**: %s\n", mdCode(r.Target))
	fmt.Fprintf(w, "- **검사 시각**: %s\n", r.ScannedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "- **소요 시간**: %dms\n", r.Summary.DurationMS)
	fmt.Fprintf(w, "- **secrethound 버전**: %s\n", mdCell(r.Version))
	fmt.Fprintln(w)

	writeMarkdownVerdict(w, r)
	writeMarkdownSummary(w, r)

	if len(r.Findings) > 0 {
		writeMarkdownFindings(w, r.Findings)
		writeMarkdownLegend(w)
	}

	writeMarkdownRemediation(w, r.Findings)
	return nil
}

// writeMarkdownVerdict는 표를 읽기 전에 "그래서 괜찮은가"에 먼저 답한다.
// 리포트를 처음 여는 사람이 알고 싶은 건 숫자가 아니라 이 한 줄이다.
func writeMarkdownVerdict(w io.Writer, r Report) {
	if r.Summary.Findings == 0 {
		fmt.Fprintln(w, "> ✅ **유출된 시크릿을 찾지 못했습니다.**")
		if r.Summary.CommitsScanned == 0 {
			fmt.Fprintln(w, ">")
			fmt.Fprintln(w, "> 단, 지금 있는 파일만 검사했습니다. 과거 커밋에 남아있는 키까지 보려면")
			fmt.Fprintln(w, "> 히스토리 검사를 함께 켜야 합니다.")
		}
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintf(w, "> 🚨 **유출된 것으로 보이는 키 %d건을 찾았습니다.**\n", r.Summary.Findings)
	fmt.Fprintln(w, ">")
	fmt.Fprintln(w, "> 한 번이라도 커밋된 키는 이미 노출된 것으로 봐야 합니다.")
	fmt.Fprintln(w, "> **파일에서 지우기 전에 발급처에서 키를 먼저 폐기(revoke)하세요.**")
	fmt.Fprintln(w, "> 지우기만 하면 키는 그대로 살아있습니다.")
	fmt.Fprintln(w)
}

func writeMarkdownSummary(w io.Writer, r Report) {
	fmt.Fprintln(w, "## 한눈에 보기")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| 항목 | 값 |")
	fmt.Fprintln(w, "|---|---|")

	detected := fmt.Sprintf("%d건", r.Summary.Findings)
	if b := SeverityBreakdown(r.Summary.BySeverity); b != "" {
		detected += " (" + b + ")"
	}
	fmt.Fprintf(w, "| 탐지 | %s |\n", detected)
	fmt.Fprintf(w, "| 검사한 파일 | %d개 (%d개 제외) |\n", r.Summary.FilesScanned, r.Summary.FilesSkipped)
	if r.Summary.CommitsScanned > 0 {
		fmt.Fprintf(w, "| 검사한 커밋 | %d개 |\n", r.Summary.CommitsScanned)
	}
	fmt.Fprintf(w, "| 오탐 필터로 제외 | %d건 |\n", r.Summary.FilteredOut)
	if r.Summary.BaselineKnown > 0 {
		fmt.Fprintf(w, "| baseline으로 제외 | %d건 (이미 알고 있던 시크릿) |\n", r.Summary.BaselineKnown)
	}

	v := r.Summary.Validation
	if v != nil {
		line := fmt.Sprintf("유효 %d, 폐기됨 %d, 검증불가 %d", v.Valid, v.Revoked, v.Unknown)
		if v.Unsupported > 0 {
			line += fmt.Sprintf(" (검증기 없는 룰 %d건 제외)", v.Unsupported)
		}
		fmt.Fprintf(w, "| 키 생존 확인 | %s |\n", line)
	}
	fmt.Fprintln(w)

	if v == nil {
		return
	}
	if v.Offline {
		fmt.Fprintln(w, "> ⚠️ 네트워크에 연결하지 못해 일부 키는 생존 확인을 건너뛰었습니다.")
		fmt.Fprintln(w)
	}
	if v.Valid > 0 {
		fmt.Fprintf(w, "> 🔴 **지금도 살아있는 키 %d건**이 확인되었습니다. 이것부터 폐기하세요.\n", v.Valid)
		fmt.Fprintln(w)
	}
}

func writeMarkdownFindings(w io.Writer, findings []finding.Finding) {
	fmt.Fprintln(w, "## 탐지 목록")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| 심각도 | 위치 | 종류 | 값 | 신뢰도 | 비고 |")
	fmt.Fprintln(w, "|---|---|---|---|---:|---|")

	for _, f := range findings {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %s |\n",
			strings.ToUpper(string(f.Severity)),
			mdCode(location(f)),
			mdCell(f.RuleID),
			mdCode(f.Masked),
			f.Confidence,
			markdownNote(f))
	}
	fmt.Fprintln(w)
}

// markdownNote는 텍스트 출력의 annotation과 같은 정보를 담되, 신뢰도가 이미
// 별도 열에 있으므로 빼고 나머지를 문장에 가깝게 풀어 쓴다.
func markdownNote(f finding.Finding) string {
	var parts []string
	if f.Occurrences > 1 {
		parts = append(parts, fmt.Sprintf("%d곳에서 발견", f.Occurrences))
	}
	if f.Commit != "" {
		if f.InWorktree {
			parts = append(parts, "현재 파일에도 남아있음")
		} else {
			parts = append(parts, "과거 커밋에만 남아있음")
		}
	}
	if label := validationLabel(f.Validation); label != "" {
		parts = append(parts, label)
	}
	if len(parts) == 0 {
		return "—"
	}
	return mdCell(strings.Join(parts, ", "))
}

func writeMarkdownLegend(w io.Writer) {
	fmt.Fprintln(w, "### 표 보는 법")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "- **심각도** — 유출됐을 때 피해가 얼마나 큰지입니다. `CRITICAL` 부터 처리하세요.")
	fmt.Fprintln(w, "- **위치** — `파일:줄번호` 입니다. `@` 뒤에 붙은 7자리는 그 값이 처음 들어온 커밋을 가리킵니다.")
	fmt.Fprintln(w, "- **값** — 가운데를 가린 형태로만 싣습니다. 이 리포트 파일이 또 다른 유출 경로가 되면 안 되므로 원본은 저장하지 않습니다.")
	fmt.Fprintln(w, "- **신뢰도** — 진짜 시크릿일 가능성에 매긴 0~100 점수입니다. 50점 미만은 애초에 표에 오르지 않습니다.")
	fmt.Fprintln(w, "- **비고** — 같은 값이 여러 곳에 있는지, 지금도 파일에 남아있는지, 발급처에 물어본 결과가 있으면 그 결과입니다.")
	fmt.Fprintln(w)
}

func writeMarkdownRemediation(w io.Writer, findings []finding.Finding) {
	guides, cleanups := collectRemediation(findings)
	if len(guides) == 0 && len(cleanups) == 0 {
		return
	}

	fmt.Fprintln(w, "## 대응 방법")
	fmt.Fprintln(w)

	if len(cleanups) > 0 {
		fmt.Fprintln(w, "> ⚠️ **순서가 중요합니다.** 히스토리에서 파일만 지워도 키 자체는 여전히 유효하고,")
		fmt.Fprintln(w, "> 이미 누군가 저장소를 클론해 갔을 수 있습니다. 폐기를 먼저 하세요.")
		fmt.Fprintln(w)
	}

	if len(guides) > 0 {
		fmt.Fprintln(w, "### 발급처에서 키 폐기하기")
		fmt.Fprintln(w)
		for _, g := range guides {
			fmt.Fprintf(w, "- **%s** — %s\n", mdCell(g.ruleID), mdCell(g.text))
		}
		fmt.Fprintln(w)
	}

	if len(cleanups) > 0 {
		fmt.Fprintln(w, "### git 히스토리에서 지우기 (폐기를 마친 뒤에)")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "```bash")
		for _, cmd := range cleanups {
			fmt.Fprintln(w, cmd)
		}
		fmt.Fprintln(w, "```")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "해당 파일을 히스토리 전체에서 제거하는 명령입니다. 실행한 뒤에는 원격 저장소에")
		fmt.Fprintln(w, "강제 푸시해야 하고, 팀원 전원이 저장소를 다시 클론해야 합니다.")
		fmt.Fprintln(w, "파일 전체가 아니라 값만 지우고 싶다면 `git filter-repo --replace-text` 규칙을 직접 구성하세요.")
		fmt.Fprintln(w)
	}
}

// mdCell은 표의 셀 경계를 깨뜨리는 문자를 막는다. 표는 줄 단위로 파싱되므로
// 파이프와 개행만 처리하면 된다. 경로·룰 문구는 스캔 대상 저장소에서 오는
// 값이라 무엇이 들어올지 알 수 없다.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// mdCode는 값을 코드 스팬으로 감싼다. 값 안에 백틱이 있으면 스팬이 그 자리에서
// 끊기므로, 그때는 구분자를 더 긴 백틱으로 늘린다 (CommonMark 코드 스팬 규칙).
func mdCode(s string) string {
	s = mdCell(s)
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	// 값이 백틱으로 시작하거나 끝나면 앞뒤로 공백이 하나 있어야 스팬이 성립한다.
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}
