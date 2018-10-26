package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/cookie"
	"traefik-forward-auth/login"
	"traefik-forward-auth/providers"
	"traefik-forward-auth/session"
	"traefik-forward-auth/utils"
)

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
	if !bytes.Equal(value, []byte("{}")) {
		value = cookie.SignedValue(f.CookieSeed, f.CookieName, value, now)
		if len(value) > 4096 {
			// Cookies cannot be larger than 4kb
			log.Warningf("Cookie Size: %d bytes", len(value))
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
			log.Warningf("Request host is %q but using configured cookie domain of %q", domain, f.CookieDomain)
		}
	}

	return &http.Cookie{
		Name:     name,
		Value:    string(value),
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   f.CookieSecure,
		Expires:  now.Add(expiration),
	}
}

func (f *ForwardAuth) ClearCSRFCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, f.MakeCSRFCookie(req, []byte{}, time.Hour*-1, time.Now()))
}

func (f *ForwardAuth) SetCSRFCookie(rw http.ResponseWriter, req *http.Request, val []byte) {
	http.SetCookie(rw, f.MakeCSRFCookie(req, val, f.CookieExpire, time.Now()))
}

func (f *ForwardAuth) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) {
	clr := f.MakeSessionCookie(req, []byte{}, time.Hour*-1, time.Now())
	http.SetCookie(rw, clr)

	// ugly hack because default domain changed
	if f.CookieDomain == "" {
		clr2 := *clr
		clr2.Domain = req.URL.Host
		http.SetCookie(rw, &clr2)
	}
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

func (f *ForwardAuth) SaveSession(rw http.ResponseWriter, req *http.Request, s *session.State) error {
	s.Provider = strings.ToLower(utils.ProviderFromCtx(req).Data().Name)

	value, err := f.SessionHandler.CookieForSession(s)
	if err != nil {
		return err
	}
	f.SetSessionCookie(rw, req, value)
	return nil
}

func (f *ForwardAuth) authenticate(rw http.ResponseWriter, req *http.Request) int {
	var saveSession, clearSession, revalidated bool

	remoteAddr := utils.GetRemoteAddr(req)
	provider := utils.ProviderFromCtx(req)

	sess, sessionAge, err := f.LoadCookiedSession(req)
	if err != nil {
		log.Debugf("%s %s", remoteAddr, err)

		if provider == nil {
			return http.StatusUnauthorized
		}
	}
	if sess != nil && sessionAge > f.CookieRefresh && f.CookieRefresh != time.Duration(0) {
		log.Debugf("%s refreshing %s old sess cookie for %s (refresh after %s)", remoteAddr, sessionAge, sess, f.CookieRefresh)
		saveSession = true
	}

	if sess != nil {
		sessionProvider, _ := cfg.AliveProviders.Get(sess.Provider)

		switch {
		case provider == nil && sessionProvider != nil:
			provider = sessionProvider
		case provider == nil && sessionProvider == nil:
			log.Criticalf(`%s session: provider "%s" is not configured`, remoteAddr, sess.Provider)
			return http.StatusInternalServerError
		case provider != sessionProvider:
			log.Errorf(`%s bad session provider "%s"`, remoteAddr, sess.Provider)
			return http.StatusBadRequest
		}
	}

	if ok, err := provider.RefreshSessionIfNeeded(sess); err != nil {
		log.Errorf("%s removing sess. error refreshing access token %s %s", remoteAddr, err, sess)
		clearSession = true
		sess = nil
	} else if ok {
		saveSession = true
		revalidated = true
	}

	if sess != nil && sess.IsExpired() {
		log.Debugf("%s removing sess. token expired %s", remoteAddr, sess)
		sess = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && !revalidated && sess != nil && sess.AccessToken != "" {
		if !provider.ValidateSessionState(sess) {
			log.Errorf("%s removing sess. error validating %s", remoteAddr, sess)
			saveSession = false
			sess = nil
			clearSession = true
		}
	}

	if sess != nil && sess.Email != "" && !f.Validator(sess.Email) {
		log.Debugf("%s Permission Denied: removing sess %s", remoteAddr, sess)
		sess = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && sess != nil {
		err := f.SaveSession(rw, req, sess)
		if err != nil {
			log.Errorf("%s %s", remoteAddr, err)
			return http.StatusInternalServerError
		}
	}

	if clearSession {
		f.ClearSessionCookie(rw, req)
	}

	if sess == nil {
		return http.StatusForbidden
	}

	if f.ForwardAuthInfo {
		rw.Header().Set("X-Auth-User", sess.User)
		if sess.Email != "" {
			rw.Header().Set("X-Auth-Email", sess.Email)
		}
	}
	if f.ForwardAccessToken && sess.AccessToken != "" {
		rw.Header().Set("X-Auth-Access-Token", sess.AccessToken)
	}
	if sess.Email == "" {
		rw.Header().Set("GAP-Auth", sess.User)
	} else {
		rw.Header().Set("GAP-Auth", sess.Email)
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
	case http.StatusInternalServerError:
		f.error(rw, req, login.InternalServerError())
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
	http.Redirect(rw, req, "/", 302)
}

func (f *ForwardAuth) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	nonce, err := cookie.Nonce()
	if err != nil {
		f.error(rw, req, login.InternalError(err))
		return
	}
	f.SetCSRFCookie(rw, req, []byte(nonce))
	redirectURI := f.makeCallbackURL(req).String()
	http.Redirect(rw, req, utils.ProviderFromCtx(req).GetLoginURL(redirectURI, fmt.Sprintf("%v:%v", nonce, req.URL)), 302)
}

func (f *ForwardAuth) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	remoteAddr := utils.GetRemoteAddr(req)
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

	sess, err := redeemCode(f.makeCallbackURL(req).String(), req.Form.Get("code"), provider)
	if err != nil {
		log.Errorf("%s error redeeming code %s", remoteAddr, err)
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
		log.Warningf("%s CSRF token mismatch, potential attack", remoteAddr)
		f.error(rw, req, &login.Error{Code: http.StatusForbidden, Message: "CSRF failed"})
		return
	}

	// set cookie, or deny
	if f.Validator(sess.Email) && provider.ValidateGroup(sess.Email) {
		log.Noticef("%s authentication complete %s", remoteAddr, sess)
		err := f.SaveSession(rw, req, sess)
		if err != nil {
			log.Errorf("%s %s", remoteAddr, err)
			f.error(rw, req, login.InternalServerError())
			return
		}
		http.Redirect(rw, req, redirect, 302)
	} else {
		log.Debugf("%s Permission Denied: %q is unauthorized", remoteAddr, sess.Email)
		f.error(rw, req, &login.Error{Code: http.StatusForbidden, Message: "Invalid Account"})
	}
}

func (f *ForwardAuth) makeCallbackURL(req *http.Request) *url.URL {
	u := utils.ForwardedBaseURL(req)
	u.Path = filepath.Join(f.Path, "callback", strings.ToLower(utils.ProviderFromCtx(req).Data().Name))
	return u
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
