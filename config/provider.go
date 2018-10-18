package config

import (
	"net/url"

	"traefik-forward-auth/providers"
)

type Providers map[string]providers.Provider

func (ps Providers) Add(p providers.Provider) {
	ps[p.Data().ProviderName] = p
}

func (ps Providers) IsEmpty() bool {
	if ps == nil || len(ps) == 0 {
		return true
	}

	return false
}

func (ps Providers) AddCredentials(id, secret string, f func(*providers.ProviderData) providers.Provider, params ...interface{}) {
	if id != "" && secret != "" {
		data := &providers.ProviderData{
			ClientID:     id,
			ClientSecret: secret,
		}

		for _, param := range params {
			switch p := param.(type) {
			case LoginURL:
				data.LoginURL, _ = url.Parse(string(p))
			case RedeemURL:
				data.RedeemURL, _ = url.Parse(string(p))
			case ValidateURL:
				data.ValidateURL, _ = url.Parse(string(p))
			}
		}

		ps.Add(f(data))
	}
}

func (ps Providers) Get(name string) (p providers.Provider, ok bool) {
	p, ok = ps[name]
	return
}
