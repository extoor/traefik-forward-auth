package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"traefik-forward-auth/cookie"
	"traefik-forward-auth/login"
	"traefik-forward-auth/providers"
	"traefik-forward-auth/utils"
)

type ForwardAuth struct {
	Path string

	CookieName     string
	CookieDomain   string
	CSRFCookieName string
	CookieSeed     string
	CookieSecure   bool
	CookieCipher   *cookie.Cipher
	CookieExpire   time.Duration
	CookieRefresh  time.Duration

	Validator func(string) bool

	ForwardAuthInfo    bool
	ForwardAccessToken bool

	LoginPage http.HandlerFunc
}

func (f *ForwardAuth) MakeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	if value != "" {
		value = cookie.SignedValue(f.CookieSeed, f.CookieName, value, now)
		if len(value) > 4096 {
			// Cookies cannot be larger than 4kb
			log.Warningf("Cookie Size: %d bytes", len(value))
		}
	}
	return f.makeCookie(req, f.CookieName, value, expiration, now)
}

func (f *ForwardAuth) MakeCSRFCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return f.makeCookie(req, f.CSRFCookieName, value, expiration, now)
}

func (f *ForwardAuth) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
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
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   f.CookieSecure,
		Expires:  now.Add(expiration),
	}
}

func (f *ForwardAuth) ClearCSRFCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, f.MakeCSRFCookie(req, "", time.Hour*-1, time.Now()))
}

func (f *ForwardAuth) SetCSRFCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, f.MakeCSRFCookie(req, val, f.CookieExpire, time.Now()))
}

func (f *ForwardAuth) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) {
	clr := f.MakeSessionCookie(req, "", time.Hour*-1, time.Now())
	http.SetCookie(rw, clr)

	// ugly hack because default domain changed
	if f.CookieDomain == "" {
		clr2 := *clr
		clr2.Domain = req.URL.Host
		http.SetCookie(rw, &clr2)
	}
}

func (f *ForwardAuth) SetSessionCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, f.MakeSessionCookie(req, val, f.CookieExpire, time.Now()))
}

func (f *ForwardAuth) LoadCookiedSession(req *http.Request) (*providers.SessionState, time.Duration, error) {
	var age time.Duration

	c, err := req.Cookie(f.CookieName)
	if err != nil {
		// always http.ErrNoCookie
		return nil, age, fmt.Errorf("Cookie %q not present", f.CookieName)
	}
	val, timestamp, ok := cookie.Validate(c, f.CookieSeed, f.CookieExpire)
	if !ok {
		return nil, age, errors.New("Cookie Signature not valid")
	}

	session, err := utils.ProviderFromCtx(req).SessionFromCookie(val, f.CookieCipher)
	if err != nil {
		return nil, age, err
	}

	age = time.Now().Truncate(time.Second).Sub(timestamp)
	return session, age, nil
}

func (f *ForwardAuth) SaveSession(rw http.ResponseWriter, req *http.Request, s *providers.SessionState) error {
	value, err := utils.ProviderFromCtx(req).CookieForSession(s, f.CookieCipher)
	if err != nil {
		return err
	}
	f.SetSessionCookie(rw, req, value)
	return nil
}

func (f *ForwardAuth) authenticate(rw http.ResponseWriter, req *http.Request) int {
	var saveSession, clearSession, revalidated bool

	remoteAddr := utils.GetRemoteAddr(req)

	session, sessionAge, err := f.LoadCookiedSession(req)
	if err != nil {
		log.Debugf("%s %s", remoteAddr, err)
	}
	if session != nil && sessionAge > f.CookieRefresh && f.CookieRefresh != time.Duration(0) {
		log.Debugf("%s refreshing %s old session cookie for %s (refresh after %s)", remoteAddr, sessionAge, session, f.CookieRefresh)
		saveSession = true
	}

	provider := utils.ProviderFromCtx(req)
	if provider == nil {
		log.Critical("context: provider not found")
		return http.StatusInternalServerError
	}

	if ok, err := provider.RefreshSessionIfNeeded(session); err != nil {
		log.Errorf("%s removing session. error refreshing access token %s %s", remoteAddr, err, session)
		clearSession = true
		session = nil
	} else if ok {
		saveSession = true
		revalidated = true
	}

	if session != nil && session.IsExpired() {
		log.Debugf("%s removing session. token expired %s", remoteAddr, session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && !revalidated && session != nil && session.AccessToken != "" {
		if !provider.ValidateSessionState(session) {
			log.Errorf("%s removing session. error validating %s", remoteAddr, session)
			saveSession = false
			session = nil
			clearSession = true
		}
	}

	if session != nil && session.Email != "" && !f.Validator(session.Email) {
		log.Debugf("%s Permission Denied: removing session %s", remoteAddr, session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && session != nil {
		err := f.SaveSession(rw, req, session)
		if err != nil {
			log.Errorf("%s %s", remoteAddr, err)
			return http.StatusInternalServerError
		}
	}

	if clearSession {
		f.ClearSessionCookie(rw, req)
	}

	if session == nil {
		return http.StatusForbidden
	}

	if f.ForwardAuthInfo {
		rw.Header().Set("X-Auth-User", session.User)
		if session.Email != "" {
			rw.Header().Set("X-Auth-Email", session.Email)
		}
	}
	if f.ForwardAccessToken && session.AccessToken != "" {
		rw.Header().Set("X-Auth-Access-Token", session.AccessToken)
	}
	if session.Email == "" {
		rw.Header().Set("GAP-Auth", session.User)
	} else {
		rw.Header().Set("GAP-Auth", session.Email)
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
	f.SetCSRFCookie(rw, req, nonce)
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

	session, err := redeemCode(f.makeCallbackURL(req).String(), req.Form.Get("code"), provider)
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
	if f.Validator(session.Email) && provider.ValidateGroup(session.Email) {
		log.Noticef("%s authentication complete %s", remoteAddr, session)
		err := f.SaveSession(rw, req, session)
		if err != nil {
			log.Errorf("%s %s", remoteAddr, err)
			f.error(rw, req, login.InternalServerError())
			return
		}
		http.Redirect(rw, req, redirect, 302)
	} else {
		log.Debugf("%s Permission Denied: %q is unauthorized", remoteAddr, session.Email)
		f.error(rw, req, &login.Error{Code: http.StatusForbidden, Message: "Invalid Account"})
	}
}

func (f *ForwardAuth) makeCallbackURL(req *http.Request) *url.URL {
	u := utils.ForwardedBaseURL(req)
	u.Path = filepath.Join(f.Path, "callback", utils.ProviderFromCtx(req).Data().Name)
	return u
}

func redeemCode(u string, code string, provider providers.Provider) (s *providers.SessionState, err error) {
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
