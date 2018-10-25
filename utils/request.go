package utils

import (
	"net/http"

	"traefik-forward-auth/providers"
)

func ProviderFromCtx(req *http.Request) providers.Provider {
	p, _ := req.Context().Value("provider").(providers.Provider)
	return p
}
