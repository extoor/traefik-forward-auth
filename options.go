package main

import (
	"encoding/base64"
)

func addPadding(secret string) string {
	l := len(secret)

	if l > 32 {
		return secret[0:32]
	}

	padding := l % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(secret)
	if err == nil {
		secret = string(b)
	}
	return []byte(addPadding(secret))
}
