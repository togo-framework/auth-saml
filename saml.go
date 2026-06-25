// Package authsaml adds SAML 2.0 SSO (service-provider) login to the togo auth
// family. It configures a crewjam/saml ServiceProvider from env, exposes the
// standard SP endpoints (metadata / login / ACS), and on a verified assertion
// finds-or-creates the user by the asserted email and issues an auth session
// via the auth plugin.
//
// Configure with SAML_SP_CERT + SAML_SP_KEY (PEM keypair), SAML_IDP_METADATA_URL
// (or SAML_IDP_METADATA_XML), and SAML_ROOT_URL (the app's external base URL).
// When unconfigured the plugin still registers, but its endpoints return 501.
package authsaml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/togo-framework/togo"
)

// Config holds the SP configuration resolved from the environment.
type Config struct {
	RootURL     string // SAML_ROOT_URL, e.g. https://app.example.com
	CertPEM     string // SAML_SP_CERT
	KeyPEM      string // SAML_SP_KEY
	IDPMetaURL  string // SAML_IDP_METADATA_URL
	IDPMetaXML  string // SAML_IDP_METADATA_XML
	ReturnURL   string // SAML_RETURN_URL (post-login redirect, default "/")
}

// Provider holds the configured SAML ServiceProvider.
type Provider struct {
	k     *togo.Kernel
	cfg   Config
	sp    *saml.ServiceProvider
	ready bool
	err   error
}

func init() {
	togo.RegisterProviderFunc("auth-saml", togo.PriorityLate+10, func(k *togo.Kernel) error {
		p := &Provider{k: k, cfg: configFromEnv()}
		p.build() // best-effort; endpoints 501 until configured
		k.Set("auth-saml", p)
		if k.Router != nil {
			p.mountRoutes(k.Router)
		}
		return nil
	})
}

// FromKernel returns the auth-saml Provider.
func FromKernel(k *togo.Kernel) (*Provider, bool) {
	v, ok := k.Get("auth-saml")
	if !ok {
		return nil, false
	}
	p, ok := v.(*Provider)
	return p, ok
}

// Ready reports whether SAML is fully configured.
func (p *Provider) Ready() bool { return p.ready }

func configFromEnv() Config {
	c := Config{
		RootURL:    os.Getenv("SAML_ROOT_URL"),
		CertPEM:    os.Getenv("SAML_SP_CERT"),
		KeyPEM:     os.Getenv("SAML_SP_KEY"),
		IDPMetaURL: os.Getenv("SAML_IDP_METADATA_URL"),
		IDPMetaXML: os.Getenv("SAML_IDP_METADATA_XML"),
		ReturnURL:  os.Getenv("SAML_RETURN_URL"),
	}
	if c.ReturnURL == "" {
		c.ReturnURL = "/"
	}
	return c
}

// build constructs the saml.ServiceProvider from the config. Safe to call when
// unconfigured — it just leaves the provider not-ready.
func (p *Provider) build() {
	c := p.cfg
	if c.RootURL == "" || c.CertPEM == "" || c.KeyPEM == "" || (c.IDPMetaURL == "" && c.IDPMetaXML == "") {
		p.err = fmt.Errorf("auth-saml: not configured (need SAML_ROOT_URL, SAML_SP_CERT, SAML_SP_KEY, and SAML_IDP_METADATA_URL or _XML)")
		return
	}
	root, err := url.Parse(strings.TrimRight(c.RootURL, "/"))
	if err != nil {
		p.err = fmt.Errorf("auth-saml: bad SAML_ROOT_URL: %w", err)
		return
	}
	keypair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
	if err != nil {
		p.err = fmt.Errorf("auth-saml: bad SP keypair: %w", err)
		return
	}
	cert, err := x509.ParseCertificate(keypair.Certificate[0])
	if err != nil {
		p.err = fmt.Errorf("auth-saml: parse SP cert: %w", err)
		return
	}
	idp, err := p.loadIDPMetadata()
	if err != nil {
		p.err = err
		return
	}
	sp := &saml.ServiceProvider{
		Key:         keypair.PrivateKey.(*rsa.PrivateKey),
		Certificate: cert,
		MetadataURL: *root.ResolveReference(&url.URL{Path: "/api/auth/saml/metadata"}),
		AcsURL:      *root.ResolveReference(&url.URL{Path: "/api/auth/saml/acs"}),
		IDPMetadata: idp,
	}
	p.sp = sp
	p.ready = true
	p.err = nil
}

func (p *Provider) loadIDPMetadata() (*saml.EntityDescriptor, error) {
	var raw []byte
	if p.cfg.IDPMetaXML != "" {
		raw = []byte(p.cfg.IDPMetaXML)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.IDPMetaURL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("auth-saml: fetch IdP metadata: %w", err)
		}
		defer resp.Body.Close()
		raw, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("auth-saml: read IdP metadata: %w", err)
		}
	}
	ed := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(raw, ed); err != nil {
		// metadata may be wrapped in an EntitiesDescriptor
		eds := &saml.EntitiesDescriptor{}
		if err2 := xml.Unmarshal(raw, eds); err2 == nil && len(eds.EntityDescriptors) > 0 {
			return &eds.EntityDescriptors[0], nil
		}
		return nil, fmt.Errorf("auth-saml: parse IdP metadata: %w", err)
	}
	return ed, nil
}

// emailFromAssertion extracts the best email/identifier from a parsed assertion:
// a mail/email attribute, else the NameID.
func emailFromAssertion(a *saml.Assertion) string {
	if a == nil {
		return ""
	}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			name := strings.ToLower(attr.Name + " " + attr.FriendlyName)
			if strings.Contains(name, "email") || strings.Contains(name, "mail") {
				for _, v := range attr.Values {
					if v.Value != "" {
						return v.Value
					}
				}
			}
		}
	}
	if a.Subject != nil && a.Subject.NameID != nil {
		return a.Subject.NameID.Value
	}
	return ""
}

// safeReturn validates a return URL is a local path (anti open-redirect).
func safeReturn(raw, def string) string {
	if raw == "" {
		return def
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	return def
}
