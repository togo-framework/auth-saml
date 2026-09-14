<div align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/togo-mark-dark.svg" /><img src=".github/assets/togo-mark.svg" alt="ToGO" height="64" /></picture>
  <h1>togo-framework/auth-saml</h1>
  <p>
    <a href="https://to-go.dev/marketplace"><img src="https://img.shields.io/badge/marketplace-to--go.dev-1F8A99" alt="marketplace" /></a>
    <a href="https://pkg.go.dev/github.com/togo-framework/auth-saml"><img src="https://pkg.go.dev/badge/github.com/togo-framework/auth-saml.svg" alt="pkg.go.dev" /></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT" />
  </p>
  <p><strong>SAML 2.0 SSO (service-provider) for the <a href="https://to-go.dev">togo</a> auth family — enterprise login via Okta, Azure AD, OneLogin, etc.</strong></p>
</div>

## Install

```bash
togo install togo-framework/auth-saml
```

Adds SAML 2.0 **service-provider** login to togo. It configures a SAML SP from env, exposes the standard SP endpoints, and on a verified IdP assertion **finds-or-creates the user by the asserted email and issues an auth session** via the [`auth`](https://to-go.dev/plugins/auth) plugin. When unconfigured it registers cleanly and its endpoints return `501` (no crash).

## Configuration

| Env | Description |
|---|---|
| `SAML_ROOT_URL` | the app's external base URL, e.g. `https://app.example.com` |
| `SAML_SP_CERT` | the SP's X.509 certificate (PEM) |
| `SAML_SP_KEY` | the SP's RSA private key (PEM) |
| `SAML_IDP_METADATA_URL` | the IdP metadata URL (or use `SAML_IDP_METADATA_XML`) |
| `SAML_IDP_METADATA_XML` | the IdP metadata XML inline (alternative to the URL) |
| `SAML_RETURN_URL` | post-login redirect (default `/`) |

Generate an SP keypair:

```bash
openssl req -x509 -newkey rsa:2048 -keyout sp.key -out sp.crt -days 3650 -nodes -subj "/CN=app.example.com"
export SAML_SP_CERT="$(cat sp.crt)"  SAML_SP_KEY="$(cat sp.key)"
```

Register the SP with your IdP using the metadata at `/api/auth/saml/metadata` (Entity ID + ACS URL are derived from `SAML_ROOT_URL`).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/auth/saml/metadata` | SP metadata XML (give this to the IdP) |
| `GET` | `/api/auth/saml/login?return=/admin` | SP-initiated login → redirect to the IdP |
| `POST` | `/api/auth/saml/acs` | Assertion Consumer Service → verify, issue session, redirect |
| `GET` | `/api/auth/saml/status` | `{ "configured": bool }` |

On success the ACS issues an auth session (cookie/JWT via the `auth` plugin) and redirects to the validated `RelayState`/return URL (open-redirect-safe — local paths only).

---

<div align="center">
  <h3>Premium sponsors</h3>
  <p>
    <a href="https://id8media.com"><strong>ID8 Media</strong></a> &nbsp;·&nbsp;
    <a href="https://one-studio.co"><strong>One Studio</strong></a>
  </p>
  <p><sub>Support togo — <a href="https://github.com/sponsors/fadymondy">become a sponsor</a>.</sub></p>
</div>
