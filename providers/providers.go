package providers

import (
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/logging"
)

var (
	log = logging.GetLogger()

	Configured map[string]Provider
)

type Provider interface {
	Data() *ProviderData
	GetEmailAddress(*SessionState) (string, error)
	GetUserName(*SessionState) (string, error)
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(string) bool
	ValidateSessionState(*SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*SessionState) (bool, error)
	SessionFromCookie(string, *cookie.Cipher) (*SessionState, error)
	CookieForSession(*SessionState, *cookie.Cipher) (string, error)
}

func Add(p Provider) {
	if Configured == nil {
		Configured = make(map[string]Provider)
	}

	Configured[p.Data().ProviderName] = p
}
