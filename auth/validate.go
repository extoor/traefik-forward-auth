package auth

import (
	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/utils"
)

func IsAllowedEmail(email string) bool {
	return ValidateEmailAndDomain(email, cfg.Users, cfg.Domains)
}

func ValidateEmailAndDomain(email string, users, domains *cfg.Data) bool {
	if users.Empty() && domains.Empty() {
		return false
	}

	_, domain := utils.SplitEmail(email)

	if domains.Exists(domain) {
		return true
	}

	if users.Exists(email) {
		return true
	}

	return false
}
