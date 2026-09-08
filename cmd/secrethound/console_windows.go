//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// kernel32는 프로세스 시작 시 이미 로드되어 있으므로 이름으로 찾아도 다른 DLL이
// 끼어들 여지가 없다.
var kernel32 = syscall.NewLazyDLL("kernel32.dll")

var (
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procGetConsoleOutputCP    = kernel32.NewProc("GetConsoleOutputCP")
	procSetConsoleOutputCP    = kernel32.NewProc("SetConsoleOutputCP")
)

const codePageUTF8 = 65001

// setupConsole은 콘솔 출력 코드페이지를 UTF-8로 맞추고, 원래대로 되돌리는 함수를 준다.
//
// Go는 문자열을 UTF-8로 내보내지만 Windows 콘솔은 기본적으로 시스템 코드페이지
// (한국어 환경이면 949)로 해석한다. 맞춰주지 않으면 리포트의 한글이 전부 깨진다.
//
// 콘솔은 사용자의 것이라 빌려 쓰는 셈이므로 끝나면 반드시 되돌린다. 되돌리지 않으면
// 사용자가 그 창에서 이어서 쓰는 다른 프로그램의 출력이 깨질 수 있다.
func setupConsole() func() {
	prev, _, _ := procGetConsoleOutputCP.Call()
	if prev == 0 {
		// 콘솔이 없다 (출력이 파일이나 파이프로 나간다). 건드릴 것도 없다.
		return func() {}
	}
	if ok, _, _ := procSetConsoleOutputCP.Call(uintptr(codePageUTF8)); ok == 0 {
		return func() {}
	}

	var restored bool
	return func() {
		if restored {
			return
		}
		restored = true
		procSetConsoleOutputCP.Call(prev)
	}
}

// ownsConsole은 이 프로세스가 콘솔을 혼자 쓰고 있는지 확인한다.
//
// 탐색기에서 실행하면 그 프로그램만을 위한 콘솔 창이 새로 만들어지므로 붙어 있는
// 프로세스가 하나뿐이다. cmd나 PowerShell에서 실행하면 부모 셸도 같은 콘솔에 붙어
// 있어 둘 이상이 된다. "더블클릭으로 켜졌는가"를 이 차이로 가른다.
func ownsConsole() bool {
	var pids [8]uint32
	n, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// explorerLaunch는 탐색기에서 실행된 경우의 인자를 커맨드로 바꿔준다.
//
// 터미널을 쓰지 않는 사용자는 커맨드 이름을 입력할 방법이 없다. 그래서 아이콘을
// 더블클릭하면 폴더 선택 창을, 폴더를 아이콘 위로 끌어다 놓으면 그 폴더를 검사하도록
// 인자를 대신 채워 넣는다. 터미널에서 실행한 경우에는(ownsConsole이 거짓) 아무것도
// 바꾸지 않으므로 CLI 동작은 그대로다.
//
// 두 번째 반환값은 "이 실행이 더블클릭이었는가"이며, 호출자는 이때 창이 바로 닫히지
// 않도록 기다려야 한다.
func explorerLaunch(args []string) ([]string, bool) {
	if !ownsConsole() {
		return args, false
	}

	// 리포트는 exe 옆에 만든다. 검사 대상 폴더에 만들면 대개 그 폴더가 저장소라
	// 리포트가 같이 커밋되고, 현재 폴더에 만들면 탐색기가 준 위치라 사용자가
	// 어디를 봐야 할지 알기 어렵다.
	outDir := exeDir()

	switch {
	case len(args) == 0:
		return []string{"check", "--pick", "--out", outDir}, true
	case allDirs(args):
		// 탐색기에서는 폴더 여러 개를 한꺼번에 끌어다 놓을 수 있다.
		out := append([]string{"check"}, args...)
		return append(out, "--out", outDir), true
	}
	return args, true
}

func allDirs(paths []string) bool {
	for _, p := range paths {
		if !isDir(p) {
			return false
		}
	}
	return len(paths) > 0
}

// waitForKey는 더블클릭으로 열린 창이 결과를 보여주기도 전에 닫히지 않게 붙잡는다.
func waitForKey() {
	fmt.Print("\n창을 닫으려면 Enter 키를 누르세요...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func exeDir() string {
	path, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(path)
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
