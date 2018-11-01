package providers

import (
	"traefik-forward-auth/logging"
	"traefik-forward-auth/session"
)

var log = logging.GetLogger()

type Provider interface {
	Data() *ProviderData
	GetEmailAddress(*session.State) (string, error)
	GetUserName(*session.State) (string, error)
	Redeem(string, string) (*session.State, error)
	ValidateGroup(string) bool
	ValidateSessionState(*session.State) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*session.State) (bool, error)
}
