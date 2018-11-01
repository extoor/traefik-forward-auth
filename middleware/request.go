package middleware

import (
	"context"
	"net/http"

	"traefik-forward-auth/auth"
	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/logging"
	"traefik-forward-auth/utils"

	"github.com/dimfeld/httptreemux"
)

var log = logging.GetLogger()

type MuxHandler http.HandlerFunc

func (f MuxHandler) SetProvider(rw http.ResponseWriter, req *http.Request) {
	ctx := auth.GetContext(req)

	name := httptreemux.ContextParams(req.Context())["provider"]
	provider, err := cfg.AliveProviders.Get(name)
	if err != nil {
		log.Error(ctx.Log(err))
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if ctx.DefaultProvider && ctx.Provider != provider {
		log.Errorf(`request provider "%s" is not "%s"`, name, ctx.Provider.Data().ID())
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	} else {
		ctx.Provider = provider
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

		ctx := &auth.RequestContext{}
		ctx.RemoteAddress = utils.GetRemoteAddr(r)

		name, ok := httptreemux.ContextParams(req.Context())["provider"]
		if ok {
			provider, err := cfg.AliveProviders.Get(name)
			if err != nil {
				log.Error(ctx.Log(err))
				http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			ctx.Provider = provider
			ctx.DefaultProvider = true
		}

		next.ServeHTTP(rw, r.WithContext(context.WithValue(r.Context(), auth.ContextName, ctx)))
	})
}
