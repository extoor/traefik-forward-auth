package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/login"
	"traefik-forward-auth/providers"
	"traefik-forward-auth/session"
	"traefik-forward-auth/utils"
)

var errNoProvider = errors.New("provider not found")

type ForwardAuth struct {
	Path string

	CookieName     string
	CookieDomain   string
	CSRFCookieName string
	CookieSeed     string
	CookieSecure   bool
	CookieExpire   time.Duration
	CookieRefresh  time.Duration

	Validator func(string) bool

	ForwardAuthInfo    bool
	ForwardAccessToken bool

	LoginPage      http.HandlerFunc
	SessionHandler session.Session
}

func (f *ForwardAuth) MakeSessionCookie(req *http.Request, value []byte, expiration time.Duration, now time.Time) *http.Cookie {
	if value != nil {
		value = cookie.SignedValue(f.CookieSeed, f.CookieName, value, now)
		if len(value) > 4096 {
			// Cookies cannot be larger than 4kb
			log.Warningf("cookie size: %d bytes", len(value))
		}
	}
	return f.makeCookie(req, f.CookieName, value, expiration, now)
}

func (f *ForwardAuth) MakeCSRFCookie(req *http.Request, value []byte, expiration time.Duration, now time.Time) *http.Cookie {
	return f.makeCookie(req, f.CSRFCookieName, value, expiration, now)
}

func (f *ForwardAuth) makeCookie(req *http.Request, name string, value []byte, expiration time.Duration, now time.Time) *http.Cookie {
	domain := req.URL.Host

	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}

	if f.CookieDomain != "" {
		if !strings.HasSuffix(domain, f.CookieDomain) {
			log.Warningf("request host is %q but using configured cookie domain of %q", domain, f.CookieDomain)
		}
	}

	c := &http.Cookie{
		Name:     name,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   f.CookieSecure,
		Expires:  now.Add(expiration),
	}

	if value != nil {
		c.Value = string(value)
	}

	return c
}

func (f *ForwardAuth) ClearCSRFCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, f.MakeCSRFCookie(req, nil, time.Hour*-1, time.Now()))
}

func (f *ForwardAuth) SetCSRFCookie(rw http.ResponseWriter, req *http.Request, val []byte) {
	http.SetCookie(rw, f.MakeCSRFCookie(req, val, f.CookieExpire, time.Now()))
}

func (f *ForwardAuth) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) {
	clr := f.MakeSessionCookie(req, nil, time.Hour*-1, time.Now())
	http.SetCookie(rw, clr)

	// ugly hack because default domain changed
	//if f.CookieDomain == "" {
	//	clr2 := *clr
	//	clr2.Domain = req.URL.Host
	//	http.SetCookie(rw, &clr2)
	//}
}

func (f *ForwardAuth) SetSessionCookie(rw http.ResponseWriter, req *http.Request, val []byte) {
	http.SetCookie(rw, f.MakeSessionCookie(req, val, f.CookieExpire, time.Now()))
}

func (f *ForwardAuth) LoadCookiedSession(req *http.Request) (*session.State, time.Duration, error) {
	var age time.Duration

	c, err := req.Cookie(f.CookieName)
	if err != nil {
		// always http.ErrNoCookie
		return nil, age, fmt.Errorf(`cookie "%s" not present`, f.CookieName)
	}
	val, timestamp, ok := cookie.Validate(c, f.CookieSeed, f.CookieExpire)
	if !ok {
		return nil, age, errors.New("cookie Signature not valid")
	}

	sess, err := f.SessionHandler.SessionFromCookie(val)
	if err != nil {
		return nil, age, err
	}

	age = time.Now().Truncate(time.Second).Sub(timestamp)
	return sess, age, nil
}

func (f *ForwardAuth) SaveSession(rw http.ResponseWriter, req *http.Request, state *session.State) error {
	state.Provider = utils.ProviderFromCtx(req).Data().ID()

	value, err := f.SessionHandler.CookieForSession(state)
	if err != nil {
		return err
	}
	f.SetSessionCookie(rw, req, value)
	return nil
}

func (f *ForwardAuth) authenticate(rw http.ResponseWriter, req *http.Request) int {
	var saveSession, clearSession, revalidated bool

	addr := utils.GetRemoteAddr(req)

	// load session state
	state, sessionAge, err := f.LoadCookiedSession(req)
	if err != nil {
		log.Debug(addr.Message(err))
	}
	if state != nil && sessionAge > f.CookieRefresh && f.CookieRefresh != time.Duration(0) {
		log.Debug(addr.Messagef("refreshing %s old session cookie for %s (refresh after %s)", sessionAge, state, f.CookieRefresh))
		saveSession = true
	}

	// load provider
	provider, err := findProvider(req, state)
	if err != nil {
		if err == errNoProvider {
			log.Debug(addr.Message("unauthorized request"))
			return http.StatusUnauthorized
		}

		log.Debug(addr.Message(err))
		return http.StatusBadRequest
	}

	if ok, err := provider.RefreshSessionIfNeeded(state); err != nil {
		log.Error(addr.Messagef("removing state. error refreshing access token %s %s", err, state))
		clearSession = true
		state = nil
	} else if ok {
		saveSession = true
		revalidated = true
	}

	if state != nil && state.IsExpired() {
		log.Debug(addr.Messagef("removing state. token expired %s", state))
		state = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && !revalidated && state != nil && state.AccessToken != "" {
		if !provider.ValidateSessionState(state) {
			log.Error(addr.Messagef("removing state. error validating %s", state))
			saveSession = false
			state = nil
			clearSession = true
		}
	}

	if state != nil && state.Email != "" && !f.Validator(state.Email) {
		log.Debug(addr.Messagef("permission denied: removing state %s", state))
		state = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && state != nil {
		err := f.SaveSession(rw, req, state)
		if err != nil {
			log.Error(addr.Message(err))
			return http.StatusInternalServerError
		}
	}

	if clearSession {
		f.ClearSessionCookie(rw, req)
	}

	if state == nil {
		return http.StatusForbidden
	}

	if f.ForwardAuthInfo {
		rw.Header().Set("X-Auth-User", state.User)
		if state.Email != "" {
			rw.Header().Set("X-Auth-Email", state.Email)
		}
	}
	if f.ForwardAccessToken && state.AccessToken != "" {
		rw.Header().Set("X-Auth-Access-Token", state.AccessToken)
	}
	if state.Email == "" {
		rw.Header().Set("GAP-Auth", state.User)
	} else {
		rw.Header().Set("GAP-Auth", state.Email)
	}
	return http.StatusAccepted
}

func (f *ForwardAuth) error(rw http.ResponseWriter, req *http.Request, err *login.Error) {
	if err != nil {
		ctx := context.WithValue(req.Context(), "error", err)
		f.LoginPage(rw, req.WithContext(ctx))
		return
	}

	f.LoginPage(rw, req)
}

func (f *ForwardAuth) Login(rw http.ResponseWriter, req *http.Request) {
	status := f.authenticate(rw, req)
	switch status {
	case http.StatusInternalServerError, http.StatusBadRequest:
		f.error(rw, req, login.StatusCodeError(status))
		return
	case http.StatusForbidden:
		f.OAuthStart(rw, req)
		return
	case http.StatusUnauthorized:
		f.LoginPage(rw, req)
		return
	}

	rw.WriteHeader(status)
}

func (f *ForwardAuth) SignOut(rw http.ResponseWriter, req *http.Request) {
	f.ClearSessionCookie(rw, req)
	http.Redirect(rw, req, utils.ForwardedBaseURL(req).String(), 302)
}

func (f *ForwardAuth) getRedirectURL(req *http.Request) (u string) {
	if strings.HasPrefix(req.URL.Path, path.Join(f.Path, "login/")) {
		u = req.Referer()
	} else {
		u = req.URL.String()
	}
	return
}

func (f *ForwardAuth) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	nonce, err := cookie.Nonce()
	if err != nil {
		f.error(rw, req, login.InternalError(err))
		return
	}
	f.SetCSRFCookie(rw, req, []byte(nonce))

	callBackURL := f.makeCallbackURL(req)

	http.Redirect(rw, req, utils.ProviderFromCtx(req).GetLoginURL(callBackURL, nonce+":"+f.getRedirectURL(req)), 302)
}

func (f *ForwardAuth) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	addr := utils.GetRemoteAddr(req)
	provider := utils.ProviderFromCtx(req)

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		f.error(rw, req, login.InternalError(err))
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		f.error(rw, req, &login.Error{Code: http.StatusForbidden, Message: errorString})
		return
	}

	state, err := redeemCode(f.makeCallbackURL(req), req.Form.Get("code"), provider)
	if err != nil {
		log.Error(addr.Messagef("error redeeming code %s", err))
		f.error(rw, req, login.InternalServerError())
		return
	}

	s := strings.SplitN(req.Form.Get("state"), ":", 2)
	if len(s) != 2 {
		f.error(rw, req, login.InternalErrorString("Invalid State"))
		return
	}
	nonce := s[0]
	redirect := s[1]
	c, err := req.Cookie(f.CSRFCookieName)
	if err != nil {
		f.error(rw, req, &login.Error{Code: http.StatusForbidden, Message: err.Error()})
		return
	}
	f.ClearCSRFCookie(rw, req)
	if c.Value != nonce {
		log.Warning(addr.Message("CSRF token mismatch, potential attack"))
		f.error(rw, req, &login.Error{Code: http.StatusForbidden, Message: "CSRF failed"})
		return
	}

	// set cookie, or deny
	if f.Validator(state.Email) && provider.ValidateGroup(state.Email) {
		err := f.SaveSession(rw, req, state)
		if err != nil {
			log.Error(addr.Message(err))
			f.error(rw, req, login.InternalServerError())
			return
		}
		log.Notice(addr.Messagef("authentication complete: %s", state))
		http.Redirect(rw, req, redirect, 302)
	} else {
		log.Debug(addr.Messagef("permission denied: %q is unauthorized", state.Email))
		f.error(rw, req, &login.Error{Code: http.StatusForbidden, Message: "Invalid Account"})
	}
}

func (f *ForwardAuth) makeCallbackURL(req *http.Request) string {
	u := url.URL{
		Scheme: req.URL.Scheme,
		Host:   req.URL.Host,
		Path:   path.Join(f.Path, "callback", utils.ProviderFromCtx(req).Data().ID()),
	}
	return u.String()
}

func redeemCode(u string, code string, provider providers.Provider) (s *session.State, err error) {
	if code == "" {
		return nil, errors.New("missing code")
	}

	s, err = provider.Redeem(u, code)
	if err != nil {
		return
	}

	if s.Email == "" {
		s.Email, err = provider.GetEmailAddress(s)
	}

	if s.User == "" {
		s.User, err = provider.GetUserName(s)
		if err != nil && err.Error() == "not implemented" {
			err = nil
		}
	}
	return
}

func findProvider(req *http.Request, state *session.State) (providers.Provider, error) {
	var provider, sessionProvider providers.Provider

	provider = utils.ProviderFromCtx(req)

	if state != nil {
		sessionProvider, _ = cfg.AliveProviders.Get(state.Provider)
	}

	switch {
	case provider == nil && sessionProvider == nil:
		return nil, errNoProvider
	case provider == nil && sessionProvider != nil:
		provider = sessionProvider
	case provider != nil && sessionProvider == nil:
		break
	case provider != sessionProvider:
		return nil, fmt.Errorf(`bad session provider "%s"`, state.Provider)
	}

	return provider, nil
}
