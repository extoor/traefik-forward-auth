package login

import (
	"html/template"
	"net/http"
	"path"
	"sort"

	"traefik-forward-auth/auth"
	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/logging"
	"traefik-forward-auth/providers"
	_ "traefik-forward-auth/statik"

	"github.com/Masterminds/sprig"
	"github.com/rakyll/statik/fs"
)

var (
	loginTemplate = initTemplate()
	log           = logging.GetLogger()
)

type Providers []providers.Provider

func (s Providers) Len() int           { return len(s) }
func (s Providers) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Providers) Less(i, j int) bool { return s[i].Data().Name < s[j].Data().Name }

type tplContext struct {
	Providers Providers
	Error     *Error
	Prefix    string
}

func (t *tplContext) SetProviders(ps cfg.Providers) {
	t.Providers = make(Providers, len(ps))

	idx := 0
	for _, p := range ps {
		t.Providers[idx] = p
		idx++
	}

	sort.Sort(t.Providers)
}

func (t *tplContext) AddProvider(p providers.Provider) {
	t.Providers = append(t.Providers, p)
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
		Prefix: path.Join("/"+*cfg.Path, "login"),
	}

	if c := auth.GetContext(req); c.ProviderExists() {
		ctx.AddProvider(c.Provider)
	} else {
		ctx.SetProviders(cfg.AliveProviders)
	}

	loginTemplate.Execute(rw, ctx)
}
