//go:build !windows

package main

// 아래 셋은 Windows에서 아이콘을 더블클릭해 쓰는 경로를 위한 장치다.
// macOS·리눅스에는 그 진입점이 없고 사용자가 터미널에서 커맨드를 직접 주므로,
// 인자를 손대지 않고 콘솔 상태도 건드리지 않는다.

func setupConsole() func() { return func() {} }

func explorerLaunch(args []string) ([]string, bool) { return args, false }

func waitForKey() {}
