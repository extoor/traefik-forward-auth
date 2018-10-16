package main

import (
	"fmt"
	"net/http"
	"time"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/logging"
)

var log = logging.GetLogger()

func main() {

	if err := cfg.InitConfig(); err != nil {
		log.Fatal(err)
	}

	h := &ForwardAuth{
		Path: fmt.Sprintf("/%s", *cfg.Path),

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
			h.CookieCipher = cipher
		} else {
			log.Error(err)
		}
	}

	log.Info("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", h))
}
