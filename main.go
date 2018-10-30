package main

//go:generate statik -src=./login/template

import (
	"net/http"
	"path"
	"time"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/logging"
	"traefik-forward-auth/login"
	. "traefik-forward-auth/middleware"

	"github.com/dimfeld/httptreemux"
)

var log = logging.GetLogger()

func main() {
	if err := cfg.InitConfig(); err != nil {
		log.Fatal(err)
	}

	sess := &cookie.Session{}

	if *cfg.CookieEncrypt {
		cipher, err := cookie.NewCipher(secretBytes(*cfg.CookieSecret))
		if err == nil {
			sess.Cipher = cipher
		} else {
			log.Error(err)
		}
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

		LoginPage:      login.DefaultPage,
		SessionHandler: sess,
	}

	mux := httptreemux.NewContextMux()
	mux.NotFoundHandler = AuthHandler(auth.Login).SetDefaultProvider
	mux.GET("/favicon.ico", accepted)

	authMux := mux.NewGroup(auth.Path)
	authMux.GET("/logout", auth.SignOut)
	authMux.GET("/login/:provider", AuthHandler(auth.Login).SetProvider)
	authMux.GET("/callback/:provider", AuthHandler(auth.OAuthCallback).SetProvider)

	serverMux := httptreemux.NewContextMux()
	serverMux.GET("/", NewForwardRequest(mux).ServeHTTP)
	serverMux.GET("/auth/:provider", NewForwardRequest(mux).ServeHTTP)

	log.Info("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", serverMux))
}
