package main

//go:generate statik -src=./login/template

import (
	"net/http"
	"path"
	"time"

	"traefik-forward-auth/auth"
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

	sessionHandler := &cookie.Session{}

	if *cfg.CookieEncrypt {
		cipher, err := cookie.NewCipher(secretBytes(*cfg.CookieSecret))
		if err == nil {
			sessionHandler.Cipher = cipher
		} else {
			log.Error(err)
		}
	}

	authenticator := &ForwardAuth{
		Path: path.Clean("/" + *cfg.Path),

		CookieName:     *cfg.CookieName,
		CSRFCookieName: *cfg.CSRFCookieName,
		CookieSeed:     *cfg.CookieSecret,
		CookieSecure:   *cfg.CookieSecure,
		CookieExpire:   time.Duration(*cfg.CookieExpire) * time.Second,

		ForwardAccessToken: false,
		ForwardAuthInfo:    true,

		ValidateEmail: auth.IsAllowedEmail,
		LoginPage:     login.DefaultPage,
		Session:       sessionHandler,
	}

	mux := httptreemux.NewContextMux()
	mux.NotFoundHandler = authenticator.Login
	mux.GET("/favicon.ico", accepted)

	authMux := mux.NewGroup(authenticator.Path)
	authMux.GET("/logout", authenticator.SignOut)
	authMux.GET("/login/:provider", MuxHandler(authenticator.Login).SetProvider)
	authMux.GET("/callback/:provider", MuxHandler(authenticator.OAuthCallback).SetProvider)

	serverMux := httptreemux.NewContextMux()
	serverMux.GET("/", NewForwardRequest(mux).ServeHTTP)
	serverMux.GET("/auth/:provider", NewForwardRequest(mux).ServeHTTP)

	log.Info("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", serverMux))
}
