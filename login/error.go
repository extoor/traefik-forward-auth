package login

import "net/http"

type Error struct {
	Message string
	Code    int
	Title   string
}

func InternalError(err error) *Error {
	return InternalErrorString(err.Error())
}

func StatusCodeError(code int) *Error {
	return &Error{Code: code, Message: http.StatusText(code)}
}

func InternalErrorString(err string) *Error {
	return &Error{Message: err, Code: http.StatusInternalServerError}
}

func InternalServerError() *Error {
	return InternalErrorString(http.StatusText(http.StatusInternalServerError))
}
