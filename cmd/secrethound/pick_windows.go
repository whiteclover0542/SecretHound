//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

// pickFolder는 폴더 선택 대화상자를 띄우고 고른 경로를 돌려준다.
// 사용자가 취소하면 빈 문자열을 오류 없이 돌려준다.
//
// GUI 라이브러리를 끌어오는 대신 PowerShell에 대화상자를 맡긴다. 이 기능은
// 터미널을 쓰지 않는 사용자를 위한 편의 경로일 뿐이라, 도구 전체에 GUI 의존성을
// 더할 만한 값어치가 없다.
func pickFolder(prompt string) (string, error) {
	// 선택한 경로에 한글이 들어가는 일이 흔하다(예: 바탕 화면\내 프로젝트).
	// PowerShell 표준출력의 인코딩은 콘솔 코드페이지에 따라 달라지므로, 경로를
	// base64로 감싸 ASCII로만 주고받는다. 그러면 코드페이지가 무엇이든 값이 상한다.
	script := `Add-Type -AssemblyName System.Windows.Forms
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = ` + psQuote(prompt) + `
$d.ShowNewFolderButton = $false
if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($d.SelectedPath))
}`

	// -STA 는 폴더 선택 대화상자를 띄우는 데 필요하다.
	// 스크립트는 프로세스 인자로 전달되므로 콘솔 코드페이지의 영향을 받지 않는다.
	out, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
		"-STA", "-Command", script).Output()
	if err != nil {
		return "", fmt.Errorf("폴더 선택 창을 띄우지 못했습니다: %w", err)
	}

	encoded := strings.TrimSpace(string(out))
	if encoded == "" {
		return "", nil // 사용자가 취소했다
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("선택한 경로를 읽지 못했습니다: %w", err)
	}
	return string(decoded), nil
}

// psQuote는 PowerShell의 작은따옴표 문자열로 감싼다.
// 작은따옴표 안에서는 $ 와 백틱이 해석되지 않으므로, 따옴표 자체만 두 번 써서 막으면 된다.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
