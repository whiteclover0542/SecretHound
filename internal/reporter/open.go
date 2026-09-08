package reporter

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
)

// OpenInBrowser는 만들어진 리포트 파일을 사용자의 기본 브라우저로 연다.
//
// 터미널을 쓰지 않는 사용자가 결과 파일을 직접 찾아 열지 않아도 되게 하는 편의
// 기능이다. 스캔 결과의 정확성과는 무관하므로, 호출자는 실패해도 스캔 자체를
// 실패로 처리하지 말고 파일 경로만 안내하면 된다.
func OpenInBrowser(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("경로를 확인할 수 없습니다: %w", err)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// `cmd /c start` 는 경로에 공백이나 & 가 있으면 인자 해석이 흔들리고,
		// 첫 인자를 창 제목으로 먹는 예외까지 있다. rundll32 는 경로를 그대로
		// 하나의 인자로 받아서 그런 문제가 없다.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", abs)
	case "darwin":
		cmd = exec.Command("open", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}

	// 브라우저가 닫힐 때까지 기다리지 않는다. 스캔은 이미 끝났고, 사용자는
	// 프로그램이 곧바로 종료되기를 기대한다.
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
