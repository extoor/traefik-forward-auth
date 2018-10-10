package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/providers"

	"github.com/namsral/flag"
	"github.com/op/go-logging"
)

var (
	log    = logging.MustGetLogger("traefik-forward-auth")
	format = logging.MustStringFormatter(
		`%{color}[%{time:02 Jan 2006 15:04:05 MST}] %{shortfunc} ☕ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
)

func notPresent(val *string, msg string) bool {
	if *val == "" {
		log.Fatal(msg)
		return true
	}

	return false
}

// Main
func main() {
	// Parse options
	flag.String(flag.DefaultConfigFlagname, "", "Path to config file")
	path := flag.String("url-path", "_oauth", "Callback URL")
	lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
	clientId := flag.String("client-id", "", "*Google Client ID (required)")
	clientSecret := flag.String("client-secret", "", "*Google Client Secret (required)")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	//cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains")
	cookieSecret := flag.String("cookie-secret", "", "*Cookie secret (required)")
	cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
	authDomainList := flag.String("auth-domain", "", "Comma separated list of domains to forward auth for")
	domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	emailList := flag.String("email", "", "Comma separated list of emails to allow")
	direct := flag.Bool("direct", false, "Run in direct mode (use own hostname as oppose to X-Forwarded-Host, used for testing/development)")

	flag.Parse()

	logBackend := logging.NewLogBackend(os.Stdout, "", 0)
	logger := logging.NewBackendFormatter(logBackend, format)
	logging.SetBackend(logger)

	if notPresent(clientId, "client-id must be set") {
		return
	}
	if notPresent(clientSecret, "client-secret must be set") {
		return
	}
	if notPresent(cookieSecret, "cookie-secret must be set") {
		return
	}

	var authDomain []string
	if *authDomainList != "" {
		authDomain = strings.Split(*authDomainList, ",")
	}

	var domain []string
	if *domainList != "" {
		domain = strings.Split(*domainList, ",")
	}

	var email []string
	if *emailList != "" {
		email = strings.Split(*emailList, ",")
	}

	cipher, err := cookie.NewCipher([]byte(*cookieSecret))
	if err != nil {
		log.Error(err)
		return
	}

	// Setup
	h := &ForwardAuth{
		Path:         fmt.Sprintf("/%s", *path),
		CookieExpire: time.Duration(*lifetime) * time.Second,

		provider: providers.New(&providers.ProviderData{
			ProviderName: "Google",
			ClientID:     *clientId,
			ClientSecret: *clientSecret,
		}),

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		CookieSeed:     *cookieSecret,
		CookieSecure:   *cookieSecure,
		CookieCipher:   cipher,
		AuthDomain:     authDomain,

		Domain: domain,
		Email:  email,

		Direct: *direct,
	}

	log.Notice("Listening on :4181")
	log.Fatal(http.ListenAndServe(":4181", h))
}
