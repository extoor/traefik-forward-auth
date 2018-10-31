package utils

import (
	"net/http"
	"net/url"
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
