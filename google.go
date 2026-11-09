// Package google implements login with Google (OAuth2 + OpenID Connect userinfo).
// gtr package: passport-google.
//
//	a.Use(google.New(clientID, clientSecret, "https://app.example.com/auth/google/callback"))
//
// Identity.EmailVerified is taken from Google's email_verified. Link
// accounts by email only if it is true.
package google

import (
	"errors"
	"fmt"
	"net/http"

	"passport"
	oauth2 "passport-oauth2"
)

// Default Google endpoints.
const (
	AuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenURL    = "https://oauth2.googleapis.com/token"
	UserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	Issuer      = "https://accounts.google.com"
	JWKSURL     = "https://www.googleapis.com/oauth2/v3/certs"
)

// Option changes strategy settings.
type Option func(*oauth2.Config)

// WithScopes replaces the set of scopes (default: openid, email, profile).
func WithScopes(scopes ...string) Option { return func(c *oauth2.Config) { c.Scopes = scopes } }

// WithHTTPClient sets the HTTP client for requests to Google.
func WithHTTPClient(h *http.Client) Option { return func(c *oauth2.Config) { c.HTTPClient = h } }

// WithEndpoints overrides the endpoints (for tests with oauth2test).
func WithEndpoints(auth, token, userinfo string) Option {
	return func(c *oauth2.Config) { c.AuthURL, c.TokenURL, c.UserInfoURL = auth, token, userinfo }
}

// WithAuthParam adds a parameter to the login URL, for example
// WithAuthParam("prompt", "select_account"). An "hd" parameter (as from
// WithHostedDomain) is also enforced on the profile.
func WithAuthParam(key, value string) Option {
	return func(c *oauth2.Config) {
		if c.AuthParams == nil {
			c.AuthParams = map[string][]string{}
		}
		c.AuthParams.Set(key, value)
	}
}

// WithOpenID turns on PKCE and verification of Google's id_token (OpenID
// Connect): the profile then comes from the signed token instead of the
// userinfo endpoint. key is the 32-byte StateKey shared by all instances
// (nil: one per process). Pass the state to Callback.
func WithOpenID(key []byte) Option {
	return func(c *oauth2.Config) {
		c.PKCE, c.StateKey, c.UserInfoURL = true, key, ""
		c.OIDC = &oauth2.OIDC{Issuer: Issuer, JWKSURL: JWKSURL}
	}
}

// ErrWrongDomain: the Google account is not in the hosted domain the
// strategy is limited to (WithHostedDomain).
var ErrWrongDomain = errors.New("google: account outside the allowed Google Workspace domain")

// WithHostedDomain allows only accounts of a Google Workspace domain: it
// sets hd in the login URL and checks the profile's hd claim, which the URL
// parameter alone does not (it can be removed by the user).
func WithHostedDomain(domain string) Option { return WithAuthParam("hd", domain) }

// New creates the "google" strategy. clientID and clientSecret come from the Google Cloud
// Console; redirectURL is your callback, registered there as well.
func New(clientID, clientSecret, redirectURL string, opts ...Option) *oauth2.Strategy {
	cfg := oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
		AuthURL: AuthURL, TokenURL: TokenURL, UserInfoURL: UserInfoURL,
		Scopes: []string{"openid", "email", "profile"},
	}
	for _, o := range opts {
		o(&cfg)
	}
	mapper := MapProfile
	// hd in the login URL only filters Google's account chooser; anyone can
	// remove it from the URL. The domain is enforced on the profile here.
	if hd := cfg.AuthParams.Get("hd"); hd != "" && hd != "*" {
		mapper = func(p map[string]any) (*passport.Identity, error) {
			if got := oauth2.String(p, "hd"); got != hd {
				return nil, fmt.Errorf("%w: the account is in %q, not %q", ErrWrongDomain, got, hd)
			}
			return MapProfile(p)
		}
	}
	return oauth2.New("google", cfg, mapper)
}

// MapProfile parses Google's OpenID Connect userinfo profile.
func MapProfile(p map[string]any) (*passport.Identity, error) {
	return &passport.Identity{
		ProviderUserID: oauth2.String(p, "sub"),
		Email:          oauth2.String(p, "email"),
		EmailVerified:  oauth2.Bool(p, "email_verified"),
		Name:           oauth2.String(p, "name"),
		AvatarURL:      oauth2.String(p, "picture"),
	}, nil
}
