package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"traefik-forward-auth/cookie"
	"traefik-forward-auth/providers"
)

// Forward Auth
type ForwardAuth struct {
	Path string

	provider providers.Provider

	CookieName     string
	CookieDomain   string
	CSRFCookieName string
	CookieSeed     string
	CookieSecure   bool
	CookieCipher   *cookie.Cipher
	CookieExpire   time.Duration
	CookieRefresh  time.Duration

	Validator func(string) bool

	PassUserHeaders bool
	SetXAuthRequest bool
	PassAccessToken bool
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
	domain := redirectBase(req).Host

	if f.CookieDomain != "" {
		if h, _, err := net.SplitHostPort(domain); err == nil {
			domain = h
		}
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
		clr2.Domain = redirectBase(req).Host
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

	session, err := f.provider.SessionFromCookie(val, f.CookieCipher)
	if err != nil {
		return nil, age, err
	}

	age = time.Now().Truncate(time.Second).Sub(timestamp)
	return session, age, nil
}

func (f *ForwardAuth) SaveSession(rw http.ResponseWriter, req *http.Request, s *providers.SessionState) error {
	value, err := f.provider.CookieForSession(s, f.CookieCipher)
	if err != nil {
		return err
	}
	f.SetSessionCookie(rw, req, value)
	return nil
}

func (f *ForwardAuth) Authenticate(rw http.ResponseWriter, req *http.Request) int {
	var saveSession, clearSession, revalidated bool
	remoteAddr := getRemoteAddr(req)

	session, sessionAge, err := f.LoadCookiedSession(req)
	if err != nil {
		log.Errorf("%s %s", remoteAddr, err)
	}
	if session != nil && sessionAge > f.CookieRefresh && f.CookieRefresh != time.Duration(0) {
		log.Debugf("%s refreshing %s old session cookie for %s (refresh after %s)", remoteAddr, sessionAge, session, f.CookieRefresh)
		saveSession = true
	}

	if ok, err := f.provider.RefreshSessionIfNeeded(session); err != nil {
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
		if !f.provider.ValidateSessionState(session) {
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

	if f.PassUserHeaders {
		req.Header["X-Forwarded-User"] = []string{session.User}
		if session.Email != "" {
			req.Header["X-Forwarded-Email"] = []string{session.Email}
		}
	}
	if f.SetXAuthRequest {
		rw.Header().Set("X-Auth-Request-User", session.User)
		if session.Email != "" {
			rw.Header().Set("X-Auth-Request-Email", session.Email)
		}
	}
	if f.PassAccessToken && session.AccessToken != "" {
		req.Header["X-Forwarded-Access-Token"] = []string{session.AccessToken}
	}
	if session.Email == "" {
		rw.Header().Set("GAP-Auth", session.User)
	} else {
		rw.Header().Set("GAP-Auth", session.Email)
	}
	return http.StatusAccepted
}

func getRemoteAddr(req *http.Request) (s string) {
	if addr := req.Header.Get("X-Forwarded-For"); addr != "" {
		return addr
	}
	return req.RemoteAddr
}

func redirectBase(req *http.Request) *url.URL {
	return &url.URL{
		Scheme: req.Header.Get("X-Forwarded-Proto"),
		Host:   req.Header.Get("X-Forwarded-Host"),
	}
}

func (f *ForwardAuth) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	http.Error(rw, message, code)
}

func (f *ForwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	r, err := redirectBase(req).Parse(req.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		log.Error(err)
	}

	req.URL = r

	switch path := req.URL.Path; {
	case path == f.Path:
		f.OAuthCallback(rw, req)
	default:
		f.Default(rw, req)
	}
}

func (f *ForwardAuth) Default(rw http.ResponseWriter, req *http.Request) {
	status := f.Authenticate(rw, req)
	if status == http.StatusInternalServerError {
		f.ErrorPage(rw, http.StatusInternalServerError, "Internal Error", "Internal Error")
	} else if status == http.StatusForbidden {
		f.OAuthStart(rw, req)
	}
}

func (f *ForwardAuth) SignOut(rw http.ResponseWriter, req *http.Request) {
	f.ClearSessionCookie(rw, req)
	http.Redirect(rw, req, "/", 302)
}

func (f *ForwardAuth) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	nonce, err := cookie.Nonce()
	if err != nil {
		f.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}
	f.SetCSRFCookie(rw, req, nonce)
	redirect, err := redirectBase(req).Parse(req.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		f.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}
	redirectURI := f.GetRedirectURI(req).String()
	http.Redirect(rw, req, f.provider.GetLoginURL(redirectURI, fmt.Sprintf("%v:%v", nonce, redirect.String())), 302)
}

func (f *ForwardAuth) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	remoteAddr := getRemoteAddr(req)

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		f.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		f.ErrorPage(rw, 403, "Permission Denied", errorString)
		return
	}

	session, err := f.redeemCode(req, req.Form.Get("code"))
	if err != nil {
		log.Infof("%s error redeeming code %s", remoteAddr, err)
		f.ErrorPage(rw, 500, "Internal Error", "Internal Error")
		return
	}

	s := strings.SplitN(req.Form.Get("state"), ":", 2)
	if len(s) != 2 {
		f.ErrorPage(rw, 500, "Internal Error", "Invalid State")
		return
	}
	nonce := s[0]
	redirect := s[1]
	c, err := req.Cookie(f.CSRFCookieName)
	if err != nil {
		f.ErrorPage(rw, 403, "Permission Denied", err.Error())
		return
	}
	f.ClearCSRFCookie(rw, req)
	if c.Value != nonce {
		log.Infof("%s csrf token mismatch, potential attack", remoteAddr)
		f.ErrorPage(rw, 403, "Permission Denied", "csrf failed")
		return
	}

	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		redirect = "/"
	}

	// set cookie, or deny
	if f.Validator(session.Email) && f.provider.ValidateGroup(session.Email) {
		log.Debugf("%s authentication complete %s", remoteAddr, session)
		err := f.SaveSession(rw, req, session)
		if err != nil {
			log.Errorf("%s %s", remoteAddr, err)
			f.ErrorPage(rw, 500, "Internal Error", "Internal Error")
			return
		}
		http.Redirect(rw, req, redirect, 302)
	} else {
		log.Debugf("%s Permission Denied: %q is unauthorized", remoteAddr, session.Email)
		f.ErrorPage(rw, 403, "Permission Denied", "Invalid Account")
	}
}

func (f *ForwardAuth) GetRedirectURI(req *http.Request) *url.URL {
	u := redirectBase(req)
	u.Path = f.Path
	return u
}

func (f *ForwardAuth) redeemCode(req *http.Request, code string) (s *providers.SessionState, err error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	redirectURI := f.GetRedirectURI(req).String()
	s, err = f.provider.Redeem(redirectURI, code)
	if err != nil {
		return
	}

	if s.Email == "" {
		s.Email, err = f.provider.GetEmailAddress(s)
	}

	if s.User == "" {
		s.User, err = f.provider.GetUserName(s)
		if err != nil && err.Error() == "not implemented" {
			err = nil
		}
	}
	return
}
