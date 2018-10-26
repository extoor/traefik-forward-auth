package session

import (
	"bytes"
	"fmt"
	"time"
)

type Session interface {
	CookieForSession(*State) ([]byte, error)
	SessionFromCookie([]byte) (*State, error)
}

type UserData struct {
	Email    string `json:"email"`
	User     string `json:"user,omitempty"`
	Provider string `json:"provider"`
}

type State struct {
	UserData
	AccessToken  string
	ExpiresOn    time.Time
	RefreshToken string
}

func (s *State) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

func (s *State) String() string {
	buf := bytes.NewBufferString("Session{" + s.AccountInfo())
	if s.AccessToken != "" {
		buf.WriteString(" token:true")
	}
	if !s.ExpiresOn.IsZero() {
		buf.WriteString(" expires:" + s.ExpiresOn.String())
	}
	if s.RefreshToken != "" {
		buf.WriteString(" refresh_token:true")
	}
	buf.WriteString(" provider:" + s.Provider + "}")
	return buf.String()
}

func (s *State) AccountInfo() string {
	return fmt.Sprintf("email:%s user:%s", s.Email, s.User)
}
