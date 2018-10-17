package middleware

import (
	"context"
	"fmt"
	"net/http"

	"traefik-forward-auth/logging"
	"traefik-forward-auth/providers"
	"traefik-forward-auth/utils"
)

var log = logging.GetLogger()

func ForwardRequest(next http.Handler) http.Handler {
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

		next.ServeHTTP(rw, r)
	})
}

func SetProvider(f http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		name := req.URL.Query().Get(":provider")
		provider, found := providers.Configured[name]
		if !found {
			http.Error(rw, fmt.Sprintf(`Provider "%s" is not configured`, name), http.StatusNotFound)
			return
		}

		f(rw, AddProviderContext(req, provider))
	}
}

func AddProviderContext(req *http.Request, p providers.Provider) *http.Request {
	ctx := context.WithValue(req.Context(), "provider", p)
	return req.WithContext(ctx)
}

func Login(f http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		f(rw, AddProviderContext(req, providers.Configured["google"]))
	}
}
