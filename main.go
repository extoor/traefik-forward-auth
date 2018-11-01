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
	"traefik-forward-auth/validate"

	"github.com/dimfeld/httptreemux"
)

var log = logging.GetLogger()

func main() {
	if err := cfg.InitConfig(); err != nil {
		log.Fatal(err)
	}

	sessionHandler := &cookie.Session{}

	if *cfg.CookieEncrypt {
		cipher, err := cookie.NewCipher(secretBytes(*cfg.CookieSecret))
		if err == nil {
			sessionHandler.Cipher = cipher
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

		ForwardAccessToken: false,
		ForwardAuthInfo:    true,

		Validator: validate.IsAllowedEmail,
		LoginPage: login.DefaultPage,
		Session:   sessionHandler,
	}

	mux := httptreemux.NewContextMux()
	mux.NotFoundHandler = auth.Login
	mux.GET("/favicon.ico", accepted)

	authMux := mux.NewGroup(auth.Path)
	authMux.GET("/logout", auth.SignOut)
	authMux.GET("/login/:provider", MuxHandler(auth.Login).SetProvider)
	authMux.GET("/callback/:provider", MuxHandler(auth.OAuthCallback).SetProvider)

	serverMux := httptreemux.NewContextMux()
	serverMux.GET("/", NewForwardRequest(mux).ServeHTTP)
	serverMux.GET("/auth/:provider", NewForwardRequest(mux).ServeHTTP)

	log.Info("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", serverMux))
}
