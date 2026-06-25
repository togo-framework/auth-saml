package authsaml

import (
	"encoding/json"
	"encoding/xml"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	auth "github.com/togo-framework/auth"
)

func (p *Provider) mountRoutes(r chi.Router) {
	r.Route("/api/auth/saml", func(r chi.Router) {
		r.Get("/metadata", p.handleMetadata)
		r.Get("/login", p.handleLogin)
		r.Post("/acs", p.handleACS)
		r.Get("/status", p.handleStatus)
	})
}

func (p *Provider) handleStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"configured": p.ready}
	if !p.ready && p.err != nil {
		out["detail"] = p.err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleMetadata serves the SP metadata XML for the IdP to consume.
func (p *Provider) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if !p.ready {
		p.notConfigured(w)
		return
	}
	md := p.sp.Metadata()
	buf, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(buf)
}

// handleLogin starts an SP-initiated flow: redirect the browser to the IdP.
func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !p.ready {
		p.notConfigured(w)
		return
	}
	idpURL := p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	authReq, err := p.sp.MakeAuthenticationRequest(idpURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "saml: build authn request: "+err.Error())
		return
	}
	relayState := safeReturn(r.URL.Query().Get("return"), p.cfg.ReturnURL)
	redirect, err := authReq.Redirect(relayState, p.sp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "saml: redirect: "+err.Error())
		return
	}
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// handleACS is the Assertion Consumer Service: verify the IdP's SAML response,
// extract the email, find-or-create the user, and issue an auth session.
func (p *Provider) handleACS(w http.ResponseWriter, r *http.Request) {
	if !p.ready {
		p.notConfigured(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "saml: bad form: "+err.Error())
		return
	}
	assertion, err := p.sp.ParseResponse(r, nil)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "saml: invalid assertion: "+err.Error())
		return
	}
	email := emailFromAssertion(assertion)
	if email == "" {
		writeErr(w, http.StatusBadRequest, "saml: no email/NameID in assertion")
		return
	}

	// Issue an auth session via the auth plugin.
	a, ok := auth.FromKernel(p.k)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "saml: auth plugin not available")
		return
	}
	id, err := a.FindOrCreateByEmail(r.Context(), email)
	if err != nil || id == nil {
		writeErr(w, http.StatusInternalServerError, "saml: find-or-create user failed")
		return
	}
	if _, err := a.IssueSession(w, *id); err != nil {
		writeErr(w, http.StatusInternalServerError, "saml: issue session failed: "+err.Error())
		return
	}

	dest := safeReturn(r.Form.Get("RelayState"), p.cfg.ReturnURL)
	http.Redirect(w, r, dest, http.StatusFound)
}

func (p *Provider) notConfigured(w http.ResponseWriter) {
	detail := "SAML not configured"
	if p.err != nil {
		detail = p.err.Error()
	}
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": detail})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
