package authsaml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// genKeypair builds a self-signed SP cert/key PEM pair for tests.
func genKeypair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return
}

// minimal IdP metadata XML for a test SP build.
const idpMetadata = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func TestUnconfiguredIs501(t *testing.T) {
	p := &Provider{cfg: Config{ReturnURL: "/"}}
	p.build()
	if p.Ready() {
		t.Fatal("expected not-ready when unconfigured")
	}
	rec := httptest.NewRecorder()
	p.handleMetadata(rec, httptest.NewRequest("GET", "/api/auth/saml/metadata", nil))
	if rec.Code != 501 {
		t.Fatalf("unconfigured metadata = %d, want 501", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	p.handleLogin(rec2, httptest.NewRequest("GET", "/api/auth/saml/login", nil))
	if rec2.Code != 501 {
		t.Fatalf("unconfigured login = %d, want 501", rec2.Code)
	}
}

func TestConfiguredMetadata(t *testing.T) {
	cert, key := genKeypair(t)
	p := &Provider{cfg: Config{
		RootURL: "https://app.example.com", CertPEM: cert, KeyPEM: key,
		IDPMetaXML: idpMetadata, ReturnURL: "/",
	}}
	p.build()
	if !p.Ready() {
		t.Fatalf("expected ready, err=%v", p.err)
	}
	rec := httptest.NewRecorder()
	p.handleMetadata(rec, httptest.NewRequest("GET", "/api/auth/saml/metadata", nil))
	if rec.Code != 200 {
		t.Fatalf("metadata = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "EntityDescriptor") || !strings.Contains(body, "AssertionConsumerService") {
		t.Fatalf("metadata XML missing SP descriptors:\n%s", body[:min(300, len(body))])
	}
}

func TestLoginRedirectsToIDP(t *testing.T) {
	cert, key := genKeypair(t)
	p := &Provider{cfg: Config{
		RootURL: "https://app.example.com", CertPEM: cert, KeyPEM: key,
		IDPMetaXML: idpMetadata, ReturnURL: "/",
	}}
	p.build()
	if !p.Ready() {
		t.Fatalf("not ready: %v", p.err)
	}
	rec := httptest.NewRecorder()
	p.handleLogin(rec, httptest.NewRequest("GET", "/api/auth/saml/login?return=/admin", nil))
	if rec.Code != 302 {
		t.Fatalf("login = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.example.com/sso") {
		t.Fatalf("login redirect = %q, want IdP SSO", loc)
	}
}

func TestEmailFromAssertion(t *testing.T) {
	// email attribute wins
	a := &saml.Assertion{
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{{
				Name:         "urn:oid:0.9.2342.19200300.100.1.3",
				FriendlyName: "mail",
				Values:       []saml.AttributeValue{{Value: "alice@example.com"}},
			}},
		}},
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "alice-nameid"}},
	}
	if got := emailFromAssertion(a); got != "alice@example.com" {
		t.Fatalf("email attr = %q", got)
	}
	// falls back to NameID
	b := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "bob@example.com"}}}
	if got := emailFromAssertion(b); got != "bob@example.com" {
		t.Fatalf("nameid fallback = %q", got)
	}
	if got := emailFromAssertion(&saml.Assertion{}); got != "" {
		t.Fatalf("empty assertion = %q, want empty", got)
	}
}

func TestSafeReturn(t *testing.T) {
	cases := map[string]string{
		"/admin":              "/admin",
		"":                    "/",
		"//evil.com":          "/",
		"https://evil.com":    "/",
		"/dashboard?x=1":      "/dashboard?x=1",
	}
	for in, want := range cases {
		if got := safeReturn(in, "/"); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("SAML_ROOT_URL", "https://x.test")
	t.Setenv("SAML_RETURN_URL", "")
	c := configFromEnv()
	if c.RootURL != "https://x.test" || c.ReturnURL != "/" {
		t.Fatalf("config = %+v", c)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
