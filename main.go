package main

//go:generate statik -src=./login/template

import (
	"net/http"
	"path"
	"time"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/logging"
	. "traefik-forward-auth/middleware"

	"github.com/dimfeld/httptreemux"
)

var log = logging.GetLogger()

func main() {
	if err := cfg.InitConfig(); err != nil {
		log.Fatal(err)
	}

	auth := &ForwardAuth{
		Path: path.Clean("/" + *cfg.Path),

		CookieName:     *cfg.CookieName,
		CSRFCookieName: *cfg.CSRFCookieName,
		CookieSeed:     *cfg.CookieSecret,
		CookieSecure:   *cfg.CookieSecure,
		CookieExpire:   time.Duration(*cfg.CookieExpire) * time.Second,

		Validator: func(s string) bool {
			return true
		},

		ForwardAccessToken: false,
		ForwardAuthInfo:    true,
	}

	if *cfg.CookieEncrypt {
		cipher, err := cookie.NewCipher(secretBytes(*cfg.CookieSecret))
		if err == nil {
			auth.CookieCipher = cipher
		} else {
			log.Error(err)
		}
	}

	mux := httptreemux.NewContextMux()
	mux.NotFoundHandler = AuthHandler(auth.Default).Login

	authMux := mux.NewGroup(auth.Path)
	authMux.GET("/callback/:provider", AuthHandler(auth.OAuthCallback).SetProvider)

	serverMux := httptreemux.NewContextMux()
	serverMux.GET("/", ForwardRequest(mux).ServeHTTP)
	serverMux.GET("/auth/:provider", ForwardRequest(mux).ServeHTTP)

	log.Info("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", serverMux))
}
