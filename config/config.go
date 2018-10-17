package config

import (
	"errors"

	"traefik-forward-auth/providers"

	"github.com/namsral/flag"
)

var (
	Path               = flag.String("url-path", "_oauth", "Callback URL")
	CookieExpire       = flag.Int("cookie-expire", 43200, "Session length in seconds")
	googleClientID     = flag.String("google-client-id", "", "Google Client ID (required)")
	googleClientSecret = flag.String("google-client-secret", "", "Google Client Secret (required)")
	CookieName         = flag.String("cookie-name", "_forward_auth", "Cookie Name")
	CSRFCookieName     = flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	CookieSecret       = flag.String("cookie-secret", "", "*Cookie secret (required)")
	CookieSecure       = flag.Bool("cookie-secure", true, "Use secure cookies")
	CookieEncrypt      = flag.Bool("cookie-encrypt", true, "Use encrypted cookies")

	//cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains")
	//authDomainList := flag.String("auth-domain", "", "Comma separated list of domains to forward auth for")
	//domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	//emailList := flag.String("email", "", "Comma separated list of emails to allow")
)

func InitConfig() error {
	flag.Parse()

	switch {
	case *googleClientID != "" && *googleClientSecret != "":
		providers.Add(providers.NewGoogleProvider(&providers.ProviderData{
			ClientID:     *googleClientID,
			ClientSecret: *googleClientSecret,
		}))
	}

	if providers.Configured == nil {
		return errors.New("at least one provider must be configured")
	}

	return nil
}
