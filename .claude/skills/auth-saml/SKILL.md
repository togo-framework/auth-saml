---
name: auth-saml
description: Add SAML 2.0 SSO (service-provider) login to a togo app — configure the SP, register it with an IdP (Okta/Azure AD/OneLogin), and let the auth-saml plugin verify assertions and issue an auth session.
---

# togo auth-saml

Use this skill to add enterprise SAML SSO to a togo app.

## Configure (env)
`SAML_ROOT_URL`, `SAML_SP_CERT` + `SAML_SP_KEY` (PEM keypair), and `SAML_IDP_METADATA_URL` (or `SAML_IDP_METADATA_XML`). Optional `SAML_RETURN_URL` (default `/`).

```bash
openssl req -x509 -newkey rsa:2048 -keyout sp.key -out sp.crt -days 3650 -nodes -subj "/CN=app.example.com"
```

## Register the SP with the IdP
Give the IdP the SP metadata at `GET /api/auth/saml/metadata`. ACS = `POST /api/auth/saml/acs`.

## Endpoints
- `GET /api/auth/saml/login?return=/admin` — SP-initiated → IdP
- `POST /api/auth/saml/acs` — verify assertion → find-or-create user (auth plugin) → issue session → redirect
- `GET /api/auth/saml/metadata` — SP metadata XML
- `GET /api/auth/saml/status` — `{configured}`

## Notes
- Pairs with the `auth` plugin (it issues the session). Compose with `auth-passkeys` / `auth-oauth` for multiple login methods.
- Return URLs are local-path-validated (no open redirect). Unconfigured → 501, no crash.
