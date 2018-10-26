package main

import "net/http"

func accepted(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusAccepted)
}
