package config

import (
	"errors"

	"traefik-forward-auth/providers"

	"github.com/namsral/flag"
)

var (
	Path = flag.String("path-prefix", "_oauth", "OAuth prefix")

	//Google
	googleClientID     = flag.String("google-client-id", "", "Google client ID")
	googleClientSecret = flag.String("google-client-secret", "", "Google client secret")

	//GitHub
	githubClientID     = flag.String("github-client-id", "", "GitHub client ID")
	githubClientSecret = flag.String("github-client-secret", "", "GitHub client secret")

	//GitLab
	gitlabClientID     = flag.String("gitlab-client-id", "", "GitLab client ID")
	gitlabClientSecret = flag.String("gitlab-client-secret", "", "GitLab client secret")
	gitlabLoginURL     = flag.String("gitlab-login-url", "", "GitLab login URL")
	gitlabRedeemURL    = flag.String("gitlab-redeem-url", "", "GitLab redeem URL")
	gitlabValidateURL  = flag.String("gitlab-validate-url", "", "GitLab validate URL")

	//Cookie
	CookieName     = flag.String("cookie-name", "_forward_auth", "Cookie Name")
	CookieExpire   = flag.Int("cookie-expire", 43200, "Session length in seconds")
	CookieSecret   = flag.String("cookie-secret", "", "Cookie secret (required)")
	CookieSecure   = flag.Bool("cookie-secure", true, "Use secure cookies")
	CookieEncrypt  = flag.Bool("cookie-encrypt", true, "Use encrypted cookies")
	CSRFCookieName = flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")

	allowedDomain = flag.String("allowed-domain", "", `Comma separated list of email domains or "*" to allow`)
	allowedEmail  = flag.String("allowed-email", "", `Comma separated list of emails or "*" to allow`)

	AliveProviders = make(Providers)
	Users          *Data
	Domains        *Data
)

type (
	LoginURL    string
	RedeemURL   string
	ValidateURL string
)

func InitConfig() error {
	flag.Parse()

	AliveProviders.AddCredentials(*googleClientID, *googleClientSecret, providers.NewGoogleProvider)
	AliveProviders.AddCredentials(*githubClientID, *githubClientSecret, providers.NewGitHubProvider)
	AliveProviders.AddCredentials(*gitlabClientID, *gitlabClientSecret, providers.NewGitLabProvider,
		LoginURL(*gitlabLoginURL),
		RedeemURL(*gitlabRedeemURL),
		ValidateURL(*gitlabValidateURL),
	)

	if AliveProviders.IsEmpty() {
		return errors.New("at least one provider must be configured")
	}

	Users = NewData(*allowedEmail)
	Domains = NewData(*allowedDomain)

	return nil
}
