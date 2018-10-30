package session

import (
	"bytes"
	"strconv"
	"time"
)

type Session interface {
	CookieForSession(*State) ([]byte, error)
	SessionFromCookie([]byte) (*State, error)
}

type Login struct {
	Email    string `json:"email"`
	User     string `json:"user,omitempty"`
	Provider string `json:"provider"`
}

func (l *Login) String() string {
	var cnt int
	buf := &bytes.Buffer{}
	if l.Email != "" {
		buf.WriteString("email:" + l.Email)
		cnt++
	}
	if l.User != "" {
		AddSpace(buf, cnt)
		buf.WriteString("user:" + l.User)
		cnt++
	}
	if l.Provider != "" {
		AddSpace(buf, cnt)
		buf.WriteString("provider:" + l.Provider)
	}
	return buf.String()
}

type State struct {
	Login
	AccessToken  string   `json:"access_token,omitempty"`
	ExpiresOn    JsonTime `json:"expires_on"`
	RefreshToken string   `json:"refresh_token,omitempty"`
}

func (s *State) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

func (s *State) String() string {
	buf := bytes.NewBufferString("Session{" + s.Login.String())
	if s.AccessToken != "" {
		buf.WriteString(" token:true")
	}
	if !s.ExpiresOn.IsZero() {
		buf.WriteString(" expires:" + s.ExpiresOn.String())
	}
	if s.RefreshToken != "" {
		buf.WriteString(" refresh_token:true")
	}
	buf.WriteRune('}')
	return buf.String()
}

type JsonTime struct {
	time.Time
}

func (t *JsonTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}

	return []byte(strconv.FormatInt(t.Unix(), 10)), nil
}

func (t *JsonTime) UnmarshalJSON(buf []byte) error {
	if bytes.Equal(buf, []byte("null")) {
		return nil
	}

	i, err := strconv.ParseInt(string(buf), 10, 64)
	if err != nil {
		return err
	}

	t.Time = time.Unix(i, 0)

	return nil
}

func AddSpace(buf *bytes.Buffer, cnt int) {
	if cnt > 0 {
		buf.WriteRune(' ')
	}
}
