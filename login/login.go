package login

import (
	"html/template"
	"net/http"

	"github.com/rakyll/statik/fs"

	"traefik-forward-auth/logging"
	_ "traefik-forward-auth/statik"
)

var (
	loginTemplate = initTemplate()
	log           = logging.GetLogger()
)

func initTemplate() *template.Template {
	f, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	tpl, err := fs.ReadFile(f, "/login.html")
	if err != nil {
		log.Fatal(err)
	}
	return template.Must(template.New("login").Parse(string(tpl)))
}

func DefaultPage(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusUnauthorized)
	loginTemplate.Execute(rw, nil)
}
