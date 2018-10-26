package cookie

import (
	"errors"
	"traefik-forward-auth/session"

	"github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type Session struct {
	Cipher *Cipher
}

// CookieForSession serializes a session state for storage in a cookie
func (s *Session) CookieForSession(state *session.State) ([]byte, error) {
	if s.Cipher == nil || state.AccessToken == "" {
		return encodeSessionState(&state.User)
	}

	return encodeSessionState(state)
}

// SessionFromCookie deserializes a session from a cookie value
func (s *Session) SessionFromCookie(v []byte) (*session.State, error) {
	if s.Cipher == nil {
		return decodeSessionState(v, &session.UserData{})
	}

	return decodeSessionState(v, &session.State{})
}

func encodeSessionState(s interface{}) ([]byte, error) {
	j, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return j, nil
}

func decodeSessionState(v []byte, s interface{}) (*session.State, error) {
	if err := json.Unmarshal(v, s); err != nil {
		return nil, err
	}

	switch data := s.(type) {
	case *session.UserData:
		return &session.State{UserData: *data}, nil
	case *session.State:
		return data, nil
	}

	return nil, errors.New(`error decode "session.State"`)
}
