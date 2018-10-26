package utils

import (
	"context"
	"net/http"

	"traefik-forward-auth/providers"
)

func ProviderFromCtx(req *http.Request) providers.Provider {
	p, _ := req.Context().Value("provider").(providers.Provider)
	return p
}

func AddProviderContext(req *http.Request, p providers.Provider) *http.Request {
	ctx := context.WithValue(req.Context(), "provider", p)
	return req.WithContext(ctx)
}
