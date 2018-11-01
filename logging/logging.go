package logging

import (
	"os"

	"github.com/op/go-logging"
)

var (
	log    = logging.MustGetLogger("traefik-forward-auth")
	format = logging.MustStringFormatter(
		`%{color}[%{time:02 Jan 2006 15:04:05 MST}] %{shortfunc} ☕ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
)

func GetLogger() *logging.Logger {
	return log
}

func init() {
	logBackend := logging.NewLogBackend(os.Stdout, "", 0)
	logger := logging.NewBackendFormatter(logBackend, format)
	logging.SetBackend(logger)
	logging.SetLevel(logging.DEBUG, "")
}
