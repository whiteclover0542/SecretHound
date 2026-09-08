package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// reportSlot은 dashboard.html 안에서 리포트 JSON이 들어갈 자리를 표시하는 주석이다.
// 페이지 쪽 마크업이 바뀌어도 이 문자열만 유지되면 주입 위치는 흔들리지 않는다.
const reportSlot = "<!--SECRETHOUND_REPORT_SLOT-->"

// WriteHTML은 대시보드 페이지에 리포트를 심어 한 장짜리 HTML 파일로 내보낸다.
//
// JSON을 따로 저장한 뒤 대시보드에 끌어다 놓는 두 단계를 없애기 위한 출력이다.
// 결과 파일은 외부 의존성이 없어서 브라우저로 열면 그대로 표가 뜬다.
//
// template은 대시보드 페이지 원본이다 (보통 secrethound.Dashboard).
func WriteHTML(w io.Writer, r Report, template []byte) error {
	slot := []byte(reportSlot)
	if !bytes.Contains(template, slot) {
		return fmt.Errorf("대시보드 템플릿에서 %s 자리를 찾지 못했습니다", reportSlot)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// SetEscapeHTML은 기본값 true다. 문자열 안의 < > & 가 전부 유니코드 이스케이프로 나가므로
	// 리포트 내용이 </script> 를 만들어 페이지를 깨뜨리거나 스크립트를 주입할 수 없다.
	// 이 JSON을 <script> 블록에 그대로 심어도 되는 근거이니 끄면 안 된다.
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("리포트 직렬화 실패: %w", err)
	}

	var block bytes.Buffer
	block.WriteString(`<script id="secrethound-report" type="application/json">`)
	block.WriteByte('\n')
	block.Write(buf.Bytes())
	block.WriteString("</script>")

	_, err := w.Write(bytes.Replace(template, slot, block.Bytes(), 1))
	return err
}
