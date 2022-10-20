//go:build !with_notray

package main

import (
	_ "embed"
	"net/http"
	"strconv"
	"text/template"

	"github.com/getlantern/pac"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//go:embed pac.txt
var pacTxt string

type PACStatus int

const (
	PACON PACStatus = iota + 1
	PACOFF
	PACONGLOBAL
	PACOFFGLOBAL
)

type PAC struct {
	path      string
	localPort int
	ch        chan PACStatus
	url       string
	gurl      string
	bindAll   bool
}

func NewPAC(localPort int, path, url string, BindAll bool) *PAC {
	return &PAC{
		path:      path,
		localPort: localPort,
		ch:        make(chan PACStatus, 1),
		url:       url,
		gurl:      url + "?global=true",
		bindAll:   BindAll,
	}
}

func (p *PAC) SysPAC() {
	tpl, err := template.New(p.path).Parse(pacTxt)
	if err != nil {
		log.Fatalf("template parse pac err:%v", err)
	}

	http.HandleFunc(p.path, func(w http.ResponseWriter, r *http.Request) {
		gloabl := false

		r.ParseForm()
		globalStr := r.Form.Get("global")
		if globalStr == "true" {
			gloabl = true
		}

		w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
		tpl.Execute(w, map[string]interface{}{
			"Port":       strconv.Itoa(p.localPort),
			"Socks5Port": strconv.Itoa(p.localPort),
			"HttpPort":   strconv.Itoa(p.localPort + 1000),
			"Global":     gloabl,
		})
	})

	if err := p.pacOn(p.url); err != nil {
		log.Fatalf("set system pac err:%v", err)
	}
	defer p.pacOff(p.url)

	go p.pacManage()

	var addr string
	if p.bindAll {
		addr = ":" + strconv.Itoa(p.localPort+1)
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(p.localPort+1)
	}
	log.Infof("starting pac server at :%v", addr)

	log.Fatalln(http.ListenAndServe(addr, nil))
}

func (p *PAC) pacOn(path string) error {
	if err := pac.EnsureHelperToolPresent("pac-cmd", "Set proxy auto config", ""); err != nil {
		return errors.WithStack(err)
	}
	if err := pac.On(path); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (p *PAC) pacOff(path string) error {
	return errors.WithStack(pac.Off(path))
}

func (p *PAC) pacManage() {
	for status := range p.ch {
		switch status {
		case PACON:
			p.pacOn(p.url)
		case PACOFF:
			p.pacOff(p.url)
		case PACONGLOBAL:
			p.pacOn(p.gurl)
		case PACOFFGLOBAL:
			p.pacOff(p.gurl)
		default:
			log.Errorf("unknown pac status:%v", status)
		}
	}
}
