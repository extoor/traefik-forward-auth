package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"traefik-forward-auth/cookie"
	"traefik-forward-auth/logging"
	"traefik-forward-auth/providers"

	"github.com/namsral/flag"
)

var log = logging.GetLogger()

func notPresent(val *string, msg string) bool {
	if *val == "" {
		log.Fatal(msg)
		return true
	}

	return false
}

// Main
func main() {
	// Parse options
	flag.String(flag.DefaultConfigFlagname, "", "Path to config file")
	path := flag.String("url-path", "_oauth", "Callback URL")
	lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
	clientId := flag.String("client-id", "", "*Google Client ID (required)")
	clientSecret := flag.String("client-secret", "", "*Google Client Secret (required)")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	//cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains")
	cookieSecret := flag.String("cookie-secret", "", "*Cookie secret (required)")
	cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
	cookieEncrypt := flag.Bool("cookie-encrypt", true, "Use encrypted cookies")
	//authDomainList := flag.String("auth-domain", "", "Comma separated list of domains to forward auth for")
	//domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	//emailList := flag.String("email", "", "Comma separated list of emails to allow")

	flag.Parse()

	if notPresent(clientId, "client-id must be set") {
		return
	}
	if notPresent(clientSecret, "client-secret must be set") {
		return
	}
	if notPresent(cookieSecret, "cookie-secret must be set") {
		return
	}

	h := &ForwardAuth{
		Path: fmt.Sprintf("/%s", *path),

		provider: providers.NewGoogleProvider(&providers.ProviderData{
			ClientID:          *clientId,
			ClientSecret:      *clientSecret,
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProfileURL:        &url.URL{},
			ProtectedResource: &url.URL{},
			ValidateURL:       &url.URL{},
		}),

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		CookieSeed:     *cookieSecret,
		CookieSecure:   *cookieSecure,
		CookieExpire:   time.Duration(*lifetime) * time.Second,

		Validator: func(s string) bool {
			return true
		},

		ForwardAccessToken: false,
		ForwardAuthInfo:    true,
	}

	if *cookieEncrypt {
		cipher, err := cookie.NewCipher(secretBytes(*cookieSecret))
		if err == nil {
			h.CookieCipher = cipher
		} else {
			log.Error(err)
		}
	}

	log.Info("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", h))
}
