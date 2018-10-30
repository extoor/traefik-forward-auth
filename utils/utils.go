package utils

import (
	"fmt"
	"net/http"
	"net/url"
)

type RemoteAddress string

func (addr RemoteAddress) Messagef(format string, args ...interface{}) string {
	return string(addr) + " " + fmt.Sprintf(format, args...)
}

func (addr RemoteAddress) Message(msg interface{}) string {
	return fmt.Sprintf("%s %s", addr, msg)
}

func ForwardedBaseURL(req *http.Request) *url.URL {
	return &url.URL{
		Scheme: req.Header.Get("X-Forwarded-Proto"),
		Host:   req.Header.Get("X-Forwarded-Host"),
	}
}

func GetRemoteAddr(req *http.Request) (s RemoteAddress) {
	if addr := req.Header.Get("X-Forwarded-For"); addr != "" {
		return RemoteAddress(addr)
	}
	return RemoteAddress(req.RemoteAddr)
}
