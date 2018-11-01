package utils

import (
	"net/http"
	"net/url"
	"strings"
)

func ForwardedBaseURL(req *http.Request) *url.URL {
	return &url.URL{
		Scheme: req.Header.Get("X-Forwarded-Proto"),
		Host:   req.Header.Get("X-Forwarded-Host"),
	}
}

func GetRemoteAddr(req *http.Request) string {
	if addr := req.Header.Get("X-Forwarded-For"); addr != "" {
		return addr
	}
	return req.RemoteAddr
}

func SplitEmail(email string) (user, domain string) {
	if i := strings.IndexRune(email, '@'); i != -1 {
		user, domain = email[:i], email[i+1:]
	}

	return
}
