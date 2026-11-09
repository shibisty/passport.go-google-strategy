package google_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	google "passport-google"
	"passport-oauth2/oauth2test"
)

func TestCallback(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{
		"sub": "1093", "email": "ann@gmail.com", "email_verified": true, "name": "Ann", "picture": "https://p/a.jpg",
	})
	s := google.New(p.ClientID, p.ClientSecret, "https://app/cb", google.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL()))
	id, err := s.Callback(context.Background(), map[string]string{"code": p.Code})
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "google" || id.ProviderUserID != "1093" || id.Email != "ann@gmail.com" || !id.EmailVerified || id.Name != "Ann" || id.AvatarURL != "https://p/a.jpg" {
		t.Fatalf("identity = %+v", *id)
	}
}

func TestUnverifiedEmail(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{"sub": "1", "email": "x@y", "email_verified": false})
	s := google.New(p.ClientID, p.ClientSecret, "cb", google.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL()))
	id, err := s.Callback(context.Background(), map[string]string{"code": p.Code})
	if err != nil || id.EmailVerified {
		t.Fatalf("unverified email must stay unverified: %+v, %v", id, err)
	}
}

func TestDefaultsAndOptions(t *testing.T) {
	client := &http.Client{}
	s := google.New("cid", "sec", "https://app/cb",
		google.WithScopes("openid", "email"), google.WithHTTPClient(client),
		google.WithAuthParam("prompt", "select_account"), google.WithAuthParam("hd", "example.com"))
	cfg := s.Config()
	if cfg.AuthURL != google.AuthURL || cfg.TokenURL != google.TokenURL || cfg.UserInfoURL != google.UserInfoURL {
		t.Fatalf("default endpoints: %+v", cfg)
	}
	if cfg.HTTPClient != client || len(cfg.Scopes) != 2 || s.Name() != "google" {
		t.Fatalf("options: %+v", cfg)
	}
	u, _ := url.Parse(s.AuthCodeURL("st"))
	if q := u.Query(); q.Get("prompt") != "select_account" || q.Get("hd") != "example.com" || q.Get("scope") != "openid email" {
		t.Fatalf("auth URL: %s", u)
	}
	if def := google.New("a", "b", "c").Config(); len(def.Scopes) != 3 {
		t.Fatalf("default scopes: %v", def.Scopes)
	}
}

func TestWithOpenID(t *testing.T) {
	c := google.New("id", "secret", "https://app/cb", google.WithOpenID([]byte("0123456789abcdef0123456789abcdef"))).Config()
	if !c.PKCE || c.OIDC == nil || c.OIDC.Issuer != google.Issuer || c.OIDC.JWKSURL != google.JWKSURL || c.UserInfoURL != "" {
		t.Fatalf("WithOpenID: %+v", c)
	}
}

func TestHostedDomain(t *testing.T) {
	for name, c := range map[string]struct {
		hd   any
		want bool
	}{"same domain": {"example.com", true}, "other domain": {"gmail.com", false}, "no hd claim": {nil, false}} {
		profile := map[string]any{"sub": "1", "email": "a@example.com", "email_verified": true}
		if c.hd != nil {
			profile["hd"] = c.hd
		}
		p := oauth2test.NewProvider(t, profile)
		s := google.New(p.ClientID, p.ClientSecret, "https://app/cb",
			google.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL()), google.WithHostedDomain("example.com"))
		_, err := s.Callback(context.Background(), map[string]string{"code": p.Code})
		if (err == nil) != c.want || (!c.want && !errors.Is(err, google.ErrWrongDomain)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
