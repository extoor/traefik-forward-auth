package auth

import (
	"fmt"
	"net/http"

	cfg "traefik-forward-auth/config"
	"traefik-forward-auth/providers"
)

const ContextName = "auth_context"

type RequestContext struct {
	RemoteAddress   string
	Provider        providers.Provider
	DefaultProvider bool
}

func (c *RequestContext) ProviderExists() bool {
	return c.Provider != nil
}

func (c *RequestContext) providerEqual(p providers.Provider) bool {
	return c.Provider == p
}

func (c *RequestContext) setProvider(p providers.Provider) {
	c.Provider = p
}

func (c *RequestContext) SetProviderFromName(name string) error {
	provider, err := cfg.AliveProviders.Get(name)
	if err != nil {
		return err
	}

	if c.providerEqual(provider) {
		return nil
	}

	defer c.setProvider(provider)

	if c.ProviderExists() && c.Provider != provider {
		return fmt.Errorf(`session provider "%s" is not "%s"`, name, c.Provider.Data().ID())
	}

	return nil
}

func (c *RequestContext) Logf(format string, args ...interface{}) string {
	return c.RemoteAddress + " " + fmt.Sprintf(format, args...)
}

func (c *RequestContext) Log(msg interface{}) string {
	return fmt.Sprintf("%s %s", c.RemoteAddress, msg)
}

func GetContext(req *http.Request) *RequestContext {
	ctx, _ := req.Context().Value(ContextName).(*RequestContext)
	return ctx
}
