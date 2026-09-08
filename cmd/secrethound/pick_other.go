//go:build !windows

package main

import "fmt"

// pickFolder는 Windows에서만 지원한다.
//
// 폴더 선택 창은 터미널을 쓰지 않는 Windows 사용자를 위한 진입점(scan.bat)에서만
// 쓰인다. macOS·리눅스에서는 그 진입점이 없고 사용자가 경로를 직접 넘기므로,
// 데스크톱 환경마다 다른 대화상자 도구를 찾아 헤매는 대신 분명히 거절한다.
func pickFolder(string) (string, error) {
	return "", fmt.Errorf("폴더 선택 창은 Windows에서만 지원합니다. 검사할 폴더를 직접 지정하세요")
}
