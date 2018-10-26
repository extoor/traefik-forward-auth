package middleware

import (
	"context"
	"net/http"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/logging"
	"traefik-forward-auth/providers"
	"traefik-forward-auth/utils"

	"github.com/dimfeld/httptreemux"
)

var log = logging.GetLogger()

type AuthHandler http.HandlerFunc

func (f AuthHandler) SetProvider(rw http.ResponseWriter, req *http.Request) {
	name := httptreemux.ContextParams(req.Context())["provider"]
	provider, found := cfg.AliveProviders.Get(name)
	if !found {
		log.Errorf(`provider "%s" is not configured`, name)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	f(rw, utils.AddProviderContext(req, provider))
}

func (f AuthHandler) SetDefaultProvider(rw http.ResponseWriter, req *http.Request) {
	provider, ok := req.Context().Value("defaultProvider").(providers.Provider)
	if ok {
		f(rw, utils.AddProviderContext(req, provider))
		return
	}

	f(rw, req)
}

func NewForwardRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		u, err := utils.ForwardedBaseURL(req).Parse(req.Header.Get("X-Forwarded-Uri"))
		if err != nil {
			log.Error(err)
			http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		r := &http.Request{
			Method: req.Method,
			URL:    u,
			Header: req.Header,
		}

		name, ok := httptreemux.ContextParams(req.Context())["provider"]
		if ok {
			provider, found := cfg.AliveProviders.Get(name)
			if !found {
				log.Errorf(`provider "%s" is not configured`, name)
				http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			ctx := context.WithValue(r.Context(), "defaultProvider", provider)
			next.ServeHTTP(rw, r.WithContext(ctx))

			return
		}

		next.ServeHTTP(rw, r)
	})
}
