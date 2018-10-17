package main

import (
	"net/http"
	"time"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/logging"
	. "traefik-forward-auth/middleware"

	"github.com/gorilla/pat"
)

var log = logging.GetLogger()

func main() {
	if err := cfg.InitConfig(); err != nil {
		log.Fatal(err)
	}

	auth := &ForwardAuth{
		Path: "/" + *cfg.Path,

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

	router := pat.New()
	router.Get(auth.Path+"/callback/{provider}", SetProvider(auth.OAuthCallback))
	router.PathPrefix("/").HandlerFunc(Login(auth.Default))

	log.Info("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", ForwardRequest(router)))
}
