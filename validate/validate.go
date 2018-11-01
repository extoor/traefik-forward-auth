package validate

import (
	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/utils"
)

func IsAllowedEmail(email string) bool {
	_, domain := utils.SplitEmail(email)

	if cfg.Domains.Exists(domain) {
		return true
	}

	if cfg.Users.Exists(email) {
		return true
	}

	return false
}
