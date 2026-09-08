//go:build !windows

package main

import "fmt"

// pickFolder는 Windows에서만 지원한다.
//
// 폴더 선택 창은 Windows에서 exe 를 더블클릭했을 때만 쓰인다. macOS·리눅스에는 그
// 진입점이 없고 사용자가 경로를 직접 넘기므로, 데스크톱 환경마다 다른 대화상자 도구를
// 찾아 헤매는 대신 분명히 거절한다.
func pickFolder(string) (string, error) {
	return "", fmt.Errorf("폴더 선택 창은 Windows에서만 지원합니다. 검사할 폴더를 직접 지정하세요")
}
