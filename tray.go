package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/icon"
	"github.com/nange/easyss/util"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) trayReady() {
	if ss.config.EnableQuic {
		go ss.sessManage() // start quic session manage
	} else {
		if err := ss.InitTcpPool(); err != nil {
			log.Errorf("init tcp pool error:%v", err)
		}
	}
	go ss.SysPAC()   // system pac configuration
	go ss.Local()    // start local server
	go ss.HttpLocal() // start local http proxy server
	go ss.UDPLocal() // start local udp server

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, os.Kill, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGQUIT)
		log.Infof("receive exit signal:%v", <-c)
		ss.trayExit()
	}()

	systray.SetIcon(icon.Data)
	systray.SetTitle("Easyss")
	systray.SetTooltip("Easyss")

	cPAC := systray.AddMenuItem("启用PAC(自动代理)", "启用PAC")
	systray.AddSeparator()
	cPAC.Check() // checked as default
	cGlobal := systray.AddMenuItem("全局代理模式", "全局模式")
	systray.AddSeparator()
	cCatLog := systray.AddMenuItem("查看Easyss运行日志", "查看日志")
	systray.AddSeparator()
	cQuit := systray.AddMenuItem("退出", "退出Easyss APP")

	for {
		select {
		case <-cPAC.ClickedCh:
			if cPAC.Checked() {
				cPAC.Uncheck()

				cGlobal.Uncheck()
				cGlobal.Disable()

				ss.pac.ch <- PACOFF
			} else {
				cPAC.Check()
				cGlobal.Enable()

				ss.pac.ch <- PACON
			}
			log.Infof("pac btn clicked...is checked:%v", cPAC.Checked())
		case <-cGlobal.ClickedCh:
			if cGlobal.Disabled() {
				break
			}
			if cGlobal.Checked() {
				cGlobal.Uncheck()
				if cPAC.Checked() {
					ss.pac.ch <- PACON
				} else {
					ss.pac.ch <- PACOFFGLOBAL
				}
			} else {
				cGlobal.Check()
				ss.pac.ch <- PACONGLOBAL
			}
			log.Infof("global btn clicked... is checked:%v", cGlobal.Checked())
		case <-cCatLog.ClickedCh:
			log.Infof("cat log btn clicked...")
			if err := ss.catLog(); err != nil {
				log.Errorf("cat log err:%v", err)
			}

		case <-cQuit.ClickedCh:
			log.Infof("quit btn clicked quit now...")
			systray.Quit()
			ss.trayExit() // on linux there have some bugs, we should invoke trayExit() again
		}
	}
}

func (ss *Easyss) catLog() error {
	win := `-FilePath powershell  -WorkingDirectory "%s" -ArgumentList "-Command Get-Content %s -Wait %s"`
	if runtime.GOOS == "windows" && util.SysSupportPowershell() {
		if util.SysPowershellMajorVersion() >= 3 {
			win = fmt.Sprintf(win, util.GetCurrentDir(), ss.GetLogFileFullPathName(), "-Tail 100")
		} else {
			win = fmt.Sprintf(win, util.GetCurrentDir(), ss.GetLogFileFullPathName(), "-ReadCount 100")
		}
	}

	cmdmap := map[string][]string{
		"windows": []string{"powershell", "-Command", "Start-Process", win},
		"linux":   []string{"gnome-terminal", "--geometry=150x40+20+20", "-x", "tail", "-50f", ss.GetLogFileFullPathName()},
		"darwin":  []string{"open", "-a", "Console", ss.GetLogFileFullPathName()},
	}
	cmd := exec.Command(cmdmap[runtime.GOOS][0], cmdmap[runtime.GOOS][1:]...)
	return cmd.Start()
}

func (ss *Easyss) trayExit() {
	ss.pac.ch <- PACOFF
	if ss.tcpPool != nil {
		ss.tcpPool.Close()
	}
	time.Sleep(time.Second) // ensure the pac settings to default value
	log.Info("easyss exited...")
	os.Exit(0)
}
