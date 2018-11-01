package providers

import (
	"net/url"
	"strings"
)

type ProviderData struct {
	Name              string
	ClientID          string
	ClientSecret      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	Scope             string
	ApprovalPrompt    string
}

func (p *ProviderData) ID() string {
	return strings.ToLower(p.Name)
}

func (p *ProviderData) Data() *ProviderData { return p }
