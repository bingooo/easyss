//go:build darwin

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nange/easyss/v3/util"
)

func RunMeElevated(extraArgs ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Resolve config file to absolute path so the elevated process can find it.
	resolveConfigArg(&extraArgs)
	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		fmt.Fprintf(&argsBuilder, "'%s' ", strings.ReplaceAll(arg, "'", "'\\''"))
	}
	for _, arg := range extraArgs {
		fmt.Fprintf(&argsBuilder, "'%s' ", strings.ReplaceAll(arg, "'", "'\\''"))
	}

	cmdStr := fmt.Sprintf("'%s' %s &>/dev/null &", exe, argsBuilder.String())

	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	_, err = util.Command("osascript", "-e", script)
	return err
}

// resolveConfigArg converts any relative -c path in extraArgs to absolute.
func resolveConfigArg(extraArgs *[]string) {
	args := *extraArgs
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-c" && !filepath.IsAbs(args[i+1]) {
			if abs, err := filepath.Abs(args[i+1]); err == nil {
				args[i+1] = abs
			}
		}
	}
	*extraArgs = args
}

// SpawnTunHelper 通过带管理员权限的 osascript 启动一个常驻的提权 TUN
// helper 进程。它创建一个 FIFO 用于生命周期信号（关闭写端触发 helper
// 退出），以及一个用于接收 TUN 文件描述符的 Unix socket。完整生命周期
// 见 spawnTunHelper。
//
// 返回：
//   - fifoWriter：关闭以通知 helper 关闭
//   - fdListener：接受连接并调用 ReceiveFd 获取 TUN fd
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	// macOS 没有抽象 Unix socket：fd socket 是文件系统条目，
	// 必须在 listen 前清理陈旧文件，并在之后让提权的（root）helper
	// 可以访问。
	return spawnTunHelper(tunHelperElevator{
		label: "osascript",
		command: func(innerCmd string) *exec.Cmd {
			scriptCmd := strings.ReplaceAll(innerCmd, "\"", "\\\"")
			script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)
			return exec.Command("osascript", "-e", script)
		},
		innerCmd: func(exe, helperArgs, fifoPath string) string {
			return fmt.Sprintf("'%s' %s < '%s' &>/dev/null &", exe, helperArgs, fifoPath)
		},
		beforeListen: func(fdSocketPath string) {
			os.Remove(fdSocketPath) //nolint:errcheck
		},
		afterListen: func(fdSocketPath string) {
			// 确保提权的 helper（root）可以访问该 socket。
			os.Chmod(fdSocketPath, 0666) //nolint:errcheck
		},
		cleanupSocket: func(fdSocketPath string) {
			os.Remove(fdSocketPath) //nolint:errcheck
		},
	}, httpPort, fdSocketPath, logFile, logLevel, timeout)
}
