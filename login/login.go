package login

import (
	"html/template"
	"net/http"
	"path"

	"github.com/Masterminds/sprig"

	"github.com/rakyll/statik/fs"
	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/logging"
	"traefik-forward-auth/providers"
	_ "traefik-forward-auth/statik"
	"traefik-forward-auth/utils"
)

var (
	loginTemplate = initTemplate()
	log           = logging.GetLogger()
)

type tplContext struct {
	Providers []providers.Provider
	Error     *Error
	Prefix    string
}

func initTemplate() *template.Template {
	f, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	tpl, err := fs.ReadFile(f, "/login.html")
	if err != nil {
		log.Fatal(err)
	}
	return template.Must(template.New("login").Funcs(sprig.FuncMap()).Parse(string(tpl)))
}

func DefaultPage(rw http.ResponseWriter, req *http.Request) {
	err, ok := req.Context().Value("error").(*Error)
	if ok {
		rw.WriteHeader(err.Code)
	} else {
		rw.WriteHeader(http.StatusUnauthorized)
	}

	ctx := tplContext{
		Error:  err,
		Prefix: path.Join(path.Clean("/"+*cfg.Path), "login"),
	}

	if p := utils.ProviderFromCtx(req); p != nil {
		ctx.Providers = append(ctx.Providers, p)
	} else {
		for _, p := range cfg.AliveProviders {
			ctx.Providers = append(ctx.Providers, p)
		}
	}

	loginTemplate.Execute(rw, ctx)
}
