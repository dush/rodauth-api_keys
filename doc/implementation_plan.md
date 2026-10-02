# Implementation plan: `api_keys` feature

Status: approved. Section 9 lists the decisions.

## 1. Goal

The `api_keys` feature lets an account:

1. Create an API key with a name, an optional expiration, and optional scopes.
2. See the full API key one time only, when Rodauth creates it.
3. Show a list of its API keys.
4. Revoke an API key.

A client sends an API key in the `Authorization` header.
Rodauth authenticates the request as the account that owns the API key.
The request does not use the cookie session.

## 2. Sources

- Rodauth source, version 2.48.0 (`lib/rodauth/features/*.rb`).
- Article: [Guide to building a public-facing API with Ruby on Rails](https://therailsrunner.com/guide-to-building-public-facing-api-with-ruby-on-rails/).
- Rails `ActionController::HttpAuthentication::Token` (`TOKEN_REGEX`).

### 2.1 What the article recommends

| Topic | Recommendation | Plan decision |
|---|---|---|
| Key format | Identifiable prefix (`tkn_usr_`), underscore separator, 30 Base58 characters | Accept the prefix and separator. Use `SecureRandom.alphanumeric`, because `SecureRandom.base58` comes from ActiveSupport, not from Ruby. |
| Storage | HMAC-SHA256 digest of the full API key. No plain text in the database. | Accept. Use `compute_hmac` from Rodauth. |
| Lookup | Find the row by the digest. | Accept. Use `compute_hmacs` so that `hmac_old_secret` rotation works. |
| UI | Show the full API key one time. Later, show the prefix and a mask. | Accept. Keep a short hint column. |
| Transport | `Authorization: Bearer <key>`. `WWW-Authenticate: Bearer realm="..."` on failure. | Accept. The regexp is configurable. See section 5.1. |
| Revocation | Soft revocation with `revoked_at`. | Accept. |
| Expiration | Optional `expires_at`. | Accept. |
| Scopes | Optional `scopes` column. | Accept. See section 6. |
| Secret scanning | A prefix lets GitHub find leaked API keys. | Accept. The prefix is configurable. |

### 2.2 What to reuse from Rodauth

| Rodauth code | Source feature | Use in `api_keys` |
|---|---|---|
| `compute_hmac`, `compute_hmacs`, `hmac_secret_rotation?` | `base`, `active_sessions` | Calculate and find the key digest. Replace an old digest after secret rotation. |
| `depends :require_hmac_secret` | `active_sessions`, `remember` | Warn when `hmac_secret` is not set. |
| `session` override with a request-local hash | `jwt` | Authenticate an API request without a cookie session. |
| `Authorization` header parse, `www-authenticate` header, `return_response` | `http_basic_auth`, `jwt` | Read the API key. Send a 401 response. |
| `logged_in?` fallback | `http_basic_auth` | Let `require_login` and `require_authentication` accept an API key. |
| List and remove page with radio buttons | `webauthn` (`webauthn-remove.str`, `account_webauthn_usage`) | Revoke page. |
| Show secrets after a password check | `recovery_codes` | Create page that shows the new API key. |
| `recovery_codes_limit` | `recovery_codes` | `api_keys_limit`. |
| `last_use` column update | `webauthn`, `active_sessions` | Record the last use of an API key. |
| `after_close_account` | `active_sessions`, `remember` | Revoke all API keys of a closed account. |
| `raises_uniqueness_violation?` | `base` | Handle a digest collision (almost impossible, but safe). |
| `internal_request_method` | `remember`, `webauthn` | Create, list, and revoke API keys from a console or an admin app. |
| `json` feature | `json` | JSON responses for the management routes. No new code. |
| `audit_logging` feature | `audit_logging` | Log create and revoke actions through the `after_*` hooks. No new code. |
| `template_path` | `base` | Override it to find the templates of this gem. |

### 2.3 Dependencies

- Runtime: `rodauth` (`>= 2.48`). Rodauth brings `roda` and `sequel`.
- Ruby standard library only: `securerandom`, `openssl` (through Rodauth).
- Development only: `roda`, `sequel`, `sqlite3`, `rack-test`, `bcrypt`, `json`, `tilt`, `minitest`.

## 3. Key format

```
<prefix>_<secret>
rak_Qb4JPgNpNhcsdekspshofQVvGUcpchLRstT6HAu7EQS
```

- `prefix`: configurable. Default `"rak"`. Example values: `"myapp"`, `"myapp_live"`.
- `secret`: `SecureRandom.alphanumeric(43)`. 43 characters from 62 give approximately 256 bits.
- The secret does not contain `_` or `-`. A double-click selects the full API key.
- The database keeps:
  - the key digest: `compute_hmac(full_api_key)`, with a unique index.
  - the key hint: the prefix and the first 4 characters of the secret. The list page shows it.
- The database does not keep the full API key or the secret.

## 4. Database

```ruby
create_table(:account_api_keys) do
  primary_key :id, type: :Bignum
  foreign_key :account_id, :accounts, type: :Bignum, null: false
  String :name, null: false
  String :digest, null: false, unique: true
  String :hint, null: false
  String :scopes                # Scope names, separated by spaces (as OAuth "scope").
  DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
  DateTime :last_use
  DateTime :expires_at
  DateTime :revoked_at
  index [:account_id, :revoked_at]
end
```

Each column name is configurable with `auth_value_method`, for example `api_keys_digest_column`.

An API key is active when `revoked_at` is NULL and `expires_at` is NULL or later than `CURRENT_TIMESTAMP`.
The `active_api_keys_ds` dataset method contains this condition.

## 5. Request authentication

### 5.1 Header

The `api_key_authorization_regexp` setting finds the API key in the `Authorization` header.
The first capture group must contain the API key.
The default value uses the same scheme as Rails `TOKEN_REGEX` (`/^(Token|Bearer)\s+/`), but accepts only `Bearer` and the API key prefix:

```ruby
auth_value_methods :api_key_authorization_regexp

def api_key_authorization_regexp
  /\ABearer\s+(#{Regexp.escape(api_key_prefix)}_[A-Za-z0-9]+)\s*\z/
end
```

An application can accept `Token` too:
`api_key_authorization_regexp { /\A(?:Bearer|Token)\s+(myapp_[A-Za-z0-9]+)\s*\z/ }`.

The `jwt` feature reads each `Authorization` header that does not start with `Basic` or `Digest`.
If the application enables `jwt`, the `api_keys` feature overrides `jwt_token`.
The override returns `nil` when the header matches `api_key_authorization_regexp`.
Thus the `jwt` feature does not try to decode an API key.

### 5.2 Flow

1. Read `request.env["HTTP_AUTHORIZATION"]`.
2. If the value does not match `api_key_authorization_regexp`, do nothing.
3. Calculate `compute_hmacs(api_key)`.
4. Find a row in `active_api_keys_ds` where the digest is in the HMAC list.
5. If the query returns no row, send a 401 response with `WWW-Authenticate: Bearer realm="...", error="invalid_token"`. Do not use the cookie session as a fallback.
6. Load the account with `account_from_id(row[:account_id], account_open_status_value)`. If the account is not open, send the 401 response.
7. Set a request-local session hash:
   `{session_key => account_id, authenticated_by_session_key => ["api_key"], api_key_id_session_key => row[:id]}`.
8. Update `last_use` (see section 9).
9. If `hmac_secret_rotation?` is true and the old digest matched, write the new digest.

### 5.3 Why a request-local session

The `http_basic_auth` feature calls `login_session`. That method writes to the cookie session.
An API client does not need a cookie. A cookie also makes CSRF attacks possible.

The `jwt` feature overrides `session` and returns a hash for the request only.
The `api_keys` feature uses the same method. Thus these methods work with no change:

- `logged_in?`, `session_value`, `account_from_session`, `require_account`
- `rodauth.authenticated_by`, `current_account` in rodauth-rails

### 5.4 Public methods for the application

| Method | Description |
|---|---|
| `rodauth.api_key_authenticated?` | True if an API key authenticated the request. |
| `rodauth.require_api_key_authentication` | Send a 401 response if no valid API key is in the request. |
| `rodauth.current_api_key_id` | The ID of the API key that authenticated the request. |
| `rodauth.current_api_key_scopes` | The scopes of the API key that authenticated the request. |
| `rodauth.api_key_scope?(scope)` | True if the API key of the request has the scope. |
| `rodauth.require_api_key_scope(*scopes)` | Call `require_authentication`. Then send a 403 response if the API key does not have all the scopes. |

### 5.5 Two-factor authentication

`two_factor_base` makes `authenticated?` false when `authenticated_by` has less than two items and the account has a second factor.
The `api_keys` feature overrides `two_factor_authenticated?` to return true for an API key request.
Reason: the account used two factors when it created the API key.

This override works only when `api_keys` comes before `two_factor_base` in the method lookup.
Thus the application must enable `api_keys` after `two_factor_base` and the features that use it (`otp`, `sms_codes`, `webauthn`, `recovery_codes`).
If the order is wrong, `post_configure` raises `Rodauth::ConfigurationError`.

### 5.6 Error responses

- The 401 and 403 responses have a plain text body, for example `invalid API key`.
- When the application enables the `json` feature and the request uses JSON, the body is `{"error": "invalid API key"}`.
- Each response calls `set_error_reason`: `:invalid_api_key`, `:api_key_required`, or `:insufficient_api_key_scope`.

## 6. Scopes

- The `api_key_scopes` setting is the list of permitted scope names. Default: `[]`.
- When the list is empty, the feature does not show scopes in the form or in JSON.
- The create form shows one checkbox for each permitted scope.
- Rodauth refuses a scope name that is not in `api_key_scopes`.
- The `scopes` column keeps the selected names, separated by spaces.
- `require_api_key_scope(*scopes)` sends 403 with `WWW-Authenticate: Bearer realm="...", error="insufficient_scope", scope="..."` (RFC 6750, section 3.1).
- When `api_key_scopes` is not empty, the form requires a minimum of one scope.

## 7. Management routes

| Route | GET | POST |
|---|---|---|
| `api-keys` | Show the list of API keys. | JSON only: return the list. |
| `create-api-key` | Show a form: name, expiration date, scopes. | Create the API key. Show it one time. |
| `revoke-api-key` | Show a list of active API keys with radio buttons. | Revoke the selected API key. |

Each route:

1. Calls `require_account`.
2. Refuses a request that an API key authenticated (`authenticated_by` includes `"api_key"`). An API key must not create or revoke other API keys.
3. Asks for the password if `modifications_require_password?` is true. This follows `webauthn_remove` and `recovery_codes`.
4. Calls the hooks: `before_*_route`, `before_*`, `after_*`.
5. Uses `notice_flash`, `error_flash`, `redirect`, and `response`, as other features do.

The `create-api-key` route refuses a new API key when the account has `api_keys_limit` active API keys.
It counts the active API keys in the same transaction as the insert.

The page that shows the new API key sends `Cache-Control: no-store`. The browser and proxies must not keep a copy of the API key.

The `api_key_expires_at` parameter accepts:

- A date (`2026-12-31`). The API key expires at 23:59:59 on that day, in the time zone of the application.
- A full ISO 8601 time (`2026-12-31T12:00:00Z`).

The `api_key_scopes` parameter accepts an array (HTML check boxes `api_key_scopes[]`, or JSON) or a string with scopes separated by spaces.

JSON responses (with the `json` feature):

- `POST /create-api-key` returns `{"api_key": "rak_...", "api_key_id": 1, "name": "...", "hint": "rak_Abcd", "scopes": [...], "expires_at": "<ISO 8601 or null>", "success": "..."}`.
- `POST /api-keys` returns a list. Each item contains `id`, `name`, `hint`, `scopes`, `created_at`, `last_use`, `expires_at`, `revoked_at`. No item contains the digest.

Templates: `api-keys.str`, `create-api-key.str`, `api-key-created.str`, `revoke-api-key.str` in the `templates/` directory of this gem.
The feature overrides `template_path`. An application template with the same name has priority.

Internal request methods: `create_api_key`, `api_keys`, `revoke_api_key`.

## 8. Configuration methods (first version)

| Method | Default |
|---|---|
| `api_key_prefix` | `"rak"` |
| `api_key_secret_length` | `43` |
| `api_key_hint_length` | `4` |
| `api_key_authorization_regexp` | See section 5.1 |
| `api_key_realm` | `"api"` |
| `api_keys_table` | `:account_api_keys` |
| `api_keys_*_column` | One method for each column in section 4 |
| `api_keys_limit` | `10` active API keys for each account. `nil` removes the limit. |
| `api_key_name_max_length` | `100` |
| `api_key_scopes` | `[]` |
| `api_key_max_lifetime` | `nil` (no limit). A value makes the expiration date required. |
| `revoke_api_keys_on_password_change?` | `false` |
| `api_key_name_param`, `api_key_expires_at_param`, `api_key_scopes_param`, `api_key_id_param` | Parameter names |
| `api_key_last_use_update_interval` | `60` seconds |
| `api_keys_route`, `create_api_key_route`, `revoke_api_key_route` | Route names |

Auth methods that an application can override:
`generate_api_key`, `api_key_digest`, `api_key_hint`, `api_key_from_request`, `api_key_insert_hash`,
`create_api_key`, `revoke_api_key`, `revoke_all_api_keys`, `account_api_keys`, `valid_api_key_name?`, `valid_api_key_scopes?`.

## 9. Decisions

| Item | Decision |
|---|---|
| Header | Standard `Authorization` header. A configurable regexp, modeled on Rails `TOKEN_REGEX`. Default: `Bearer <prefix>_...`. |
| Lookup | By HMAC digest. The prefix is a public label, not a lookup value. |
| Revocation | Soft. Set `revoked_at` and keep the row. |
| Version 0.1 | HTML templates, expiration, scopes, internal requests, limit of active API keys for each account. |
| Expiration | Optional. The account selects any date. Rodauth refuses a date in the past and a date after `api_key_max_lifetime`. |
| Expiration storage | The database calculates `expires_at` with its own clock: `Sequel.date_add(CURRENT_TIMESTAMP, seconds: n)`. This follows `set_deadline_value` in Rodauth. Ruby never writes a time value. `create_api_key` takes `expires_in:` in seconds. Step 6 converts the date from the form to seconds. |
| `last_use` | Update at most one time in `api_key_last_use_update_interval` (default 60 seconds). Use one `UPDATE ... WHERE` statement. `nil` updates on each request. |
| Password change | Do not revoke API keys. The `revoke_api_keys_on_password_change?` setting (default `false`) changes this. |
| Scopes and cookie session | `require_api_key_scope` permits a request that the cookie session authenticated. Scopes limit only API keys. |
| Account without a password | Follow `two_factor_modifications_require_password?` and the `confirm_password` feature. |
| API key with no scopes | When `api_key_scopes` is not empty, the form requires a minimum of one scope. |
| Old rows | Rodauth does not remove revoked and expired rows in version 0.1. The README shows a Sequel command for the cleanup. Before `delete_account`, Rodauth removes the API key rows of the account, because of the foreign key. |

## 10. Implementation steps

1. Update the gemspec: add the `rodauth` runtime dependency and the summary. Add the development dependencies to the `Gemfile`.
2. Write the test harness: a Roda app with Rodauth, Sequel, and an SQLite in-memory database. Copy the method from `spec/spec_helper.rb` of Rodauth.
3. Add `lib/rodauth/features/api_keys.rb` with the configuration methods and the dataset methods.
4. Add `generate_api_key`, `api_key_digest`, and `create_api_key`. Write tests.
5. Add request authentication (section 5). Write tests for each security rule in `AGENTS.md`.
6. Add the `create-api-key` route, the limit check, scopes, expiration, and templates. Write HTML and JSON tests.
7. Add the `api-keys` route and the `revoke-api-key` route. Write tests.
8. Add `after_close_account` and the `jwt` integration. Write tests.
9. Add `internal_request_method` for create, list, and revoke. Write tests.
10. Write `README.md`: installation, migration, configuration, and examples.
11. Update `AGENTS.md`.
