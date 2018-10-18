package providers

import (
	"net/http"
	"net/url"

	"traefik-forward-auth/api"
)

type GitLabProvider struct {
	*ProviderData
}

func NewGitLabProvider(p *ProviderData) Provider {
	p.ProviderName = "gitlab"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/oauth/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/api/v4/user",
		}
	}
	if p.Scope == "" {
		p.Scope = "read_user"
	}
	return &GitLabProvider{ProviderData: p}
}

func (p *GitLabProvider) GetEmailAddress(s *SessionState) (string, error) {
	req, err := http.NewRequest("GET",
		p.ValidateURL.String()+"?access_token="+s.AccessToken, nil)
	if err != nil {
		log.Errorf("failed building request %s", err)
		return "", err
	}
	json, err := api.Request(req)
	if err != nil {
		log.Errorf("failed making request %s", err)
		return "", err
	}
	return json.Get("email").String()
}
