# auth-saml — usage

## 1. Configure the SP
```bash
openssl req -x509 -newkey rsa:2048 -keyout sp.key -out sp.crt -days 3650 -nodes -subj "/CN=app.example.com"
export SAML_ROOT_URL=https://app.example.com
export SAML_SP_CERT="$(cat sp.crt)"
export SAML_SP_KEY="$(cat sp.key)"
export SAML_IDP_METADATA_URL=https://your-idp/app/metadata   # or SAML_IDP_METADATA_XML
```

## 2. Register the SP with the IdP
Point the IdP at the SP metadata:
- **Metadata / Entity descriptor:** `GET https://app.example.com/api/auth/saml/metadata`
- **ACS (Assertion Consumer Service) URL:** `https://app.example.com/api/auth/saml/acs` (HTTP-POST)
- **Entity ID:** `https://app.example.com/api/auth/saml/metadata`

Okta / Azure AD / OneLogin all accept the metadata XML directly.

## 3. Log in
- SP-initiated: send users to `GET /api/auth/saml/login?return=/admin`.
- The IdP posts the assertion to `/api/auth/saml/acs`; the plugin verifies it,
  extracts the email (a `mail`/`email` attribute, else the NameID), find-or-creates
  the user via the `auth` plugin, issues an auth session, and redirects to `return`.

## Notes
- `return` / `RelayState` is validated to be a local path (open-redirect-safe).
- Unconfigured → endpoints return `501` with a clear detail; the app still boots.
- One IdP per instance in v0.1.0; multi-IdP keyed by name is a follow-up.
