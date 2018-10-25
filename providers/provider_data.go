package providers

import (
	"net/url"
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

func (p *ProviderData) Data() *ProviderData { return p }
