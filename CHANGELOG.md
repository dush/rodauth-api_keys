# Changelog

## 0.1.0 (unreleased)

First version.

- Add the `api_keys` feature for Rodauth.
- Add the `create-api-key`, `api-keys`, and `revoke-api-key` routes, with HTML templates and JSON responses.
- Authenticate a request with an API key in the `Authorization` header. The request does not use the cookie session.
- Keep only the key digest and the key hint in the database. Show the full API key one time only.
- Add scopes, an optional expiration date, and a limit of active API keys for each account.
- Record the last use of each API key.
- Revoke all API keys of an account when the account closes. Optionally revoke them when the password changes.
- Add internal request methods: `create_api_key`, `api_keys`, and `revoke_api_key`.
- Support the `json`, `jwt`, `active_sessions`, `single_session`, `two_factor_base`, `audit_logging`, and `internal_request` features.
