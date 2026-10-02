# rodauth-api_keys

The `api_keys` feature for [Rodauth](https://github.com/jeremyevans/rodauth) lets an account create, list, and revoke API keys.
A client sends an API key in the `Authorization` header. Rodauth then authenticates the request as the account that owns the API key.

```
Authorization: Bearer rak_Qb4JPgNpNhcsdekspshofQVvGUcpchLRstT6HAu7EQS
```

## Contents

- [Features](#features)
- [Installation](#installation)
- [Database migration](#database-migration)
- [Configuration](#configuration)
- [Authenticate API requests](#authenticate-api-requests)
- [Management pages](#management-pages)
- [JSON API](#json-api)
- [Internal requests](#internal-requests)
- [Configuration reference](#configuration-reference)
- [Security](#security)
- [Development](#development)

## Features

- An API key has a configurable prefix, for example `myapp_`. Secret scanners, such as GitHub secret scanning, can find a leaked API key by its prefix.
- The database keeps only an HMAC digest and a short hint of each API key. The account sees the full API key one time only.
- An API key request does not use the cookie session and does not set a cookie.
- An API key can have scopes and an expiration date.
- The account can revoke an API key. Rodauth keeps the row and sets `revoked_at`.
- Each account can have a maximum number of active API keys.
- HTML pages and JSON responses for the management routes.
- Internal request methods for create, list, and revoke.
- The feature works with the `json`, `jwt`, `two_factor_base`, `close_account`, `change_password`, `reset_password`, `audit_logging`, and `internal_request` features.

The feature uses only Rodauth and the Ruby standard library.

## Installation

Add the gem to the `Gemfile` of the application:

```ruby
gem "rodauth-api_keys"
```

Requirements:

- Ruby 3.3 or later
- Rodauth 2.48 or later

## Database migration

Add a table for the API keys. This example uses Sequel:

```ruby
Sequel.migration do
  change do
    create_table(:account_api_keys) do
      primary_key :id, type: :Bignum
      foreign_key :account_id, :accounts, type: :Bignum, null: false
      String :name, null: false
      String :digest, null: false, unique: true
      String :hint, null: false
      String :scopes
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :last_use
      DateTime :expires_at
      DateTime :revoked_at
      index [:account_id, :revoked_at]
    end
  end
end
```

If the `accounts` table uses UUID primary keys, change the type of `account_id` to `:uuid`.
You can change the table name and each column name with the configuration methods (see [Configuration reference](#configuration-reference)).

## Configuration

Enable the feature and set `hmac_secret`. The feature calculates the key digest with `hmac_secret`.

```ruby
plugin :rodauth do
  enable :login, :logout, :api_keys
  hmac_secret ENV.fetch("RODAUTH_HMAC_SECRET")

  api_key_prefix "myapp"
  api_key_scopes %w[projects:read projects:write]
  api_key_max_lifetime 86400 * 365
end
```

Feature order: enable `api_keys` after `jwt`, `two_factor_base`, and the features that use `two_factor_base` (`otp`, `sms_codes`, `webauthn`, `recovery_codes`).
If the order is wrong, Rodauth raises `Rodauth::ConfigurationError` when the application starts.

```ruby
enable :login, :logout, :jwt, :otp, :recovery_codes, :api_keys
```

## Authenticate API requests

When a request has an `Authorization: Bearer <prefix>_...` header, the feature finds the API key in the database.
If the API key is active and the account is open, these methods work as in a cookie session:

- `rodauth.require_authentication`, `rodauth.require_account`
- `rodauth.logged_in?`, `rodauth.session_value`, `rodauth.account_from_session`

If the API key is not valid, the response is `401 Unauthorized` with `WWW-Authenticate: Bearer realm="api", error="invalid_token"`.
The feature does not use the cookie session as a fallback.

Example Roda routes:

```ruby
route do |r|
  r.rodauth

  r.on "api" do
    # Accept only API keys.
    rodauth.require_api_key_authentication

    r.get "projects" do
      rodauth.require_api_key_scope("projects:read")
      # rodauth.session_value is the ID of the account that owns the API key.
      # ...
    end

    r.post "projects" do
      rodauth.require_api_key_scope("projects:write")
      # ...
    end
  end
end
```

Example client request:

```sh
curl -H "Authorization: Bearer myapp_Qb4JPgNpNhcsdekspshofQVvGUcpchLRstT6HAu7EQS" https://example.com/api/projects
```

Methods for the application:

| Method | Description |
|---|---|
| `rodauth.api_key_authenticated?` | True if an API key authenticated the request. |
| `rodauth.require_api_key_authentication` | Send `401` if no valid API key authenticated the request. |
| `rodauth.current_api_key_id` | The ID of the API key of the request, or `nil`. |
| `rodauth.current_api_key_scopes` | The scopes of the API key of the request, or `nil`. |
| `rodauth.api_key_scope?(scope)` | True if the request has the scope. A cookie session has all scopes. |
| `rodauth.require_api_key_scope(*scopes)` | Require authentication. Then send `403` with `error="insufficient_scope"` if the API key does not have all the scopes. A cookie session has all scopes. |

### Two-factor authentication

An API key counts as full authentication. The account used all its authentication factors when it created the API key.

### Last use

The feature records the time of use in `last_use`. It updates the column at most one time in `api_key_last_use_update_interval` seconds (default 60).
Set the value to `nil` to update the column on each request.

## Management pages

| Route | Description |
|---|---|
| `/api-keys` | The list of API keys of the account: name, hint, scopes, created, last use, expiration date, and status. |
| `/create-api-key` | A form to create an API key. The next page shows the full API key one time. |
| `/revoke-api-key` | A form to revoke an active API key. |

Rules for these routes:

- The account must be logged in.
- A request that an API key authenticated gets `403`. An API key cannot create or revoke API keys.
- If the account has a password, the form asks for it.
- The page that shows the new API key sends `Cache-Control: no-store`.

The expiration date field accepts a date (`2026-12-31`) or a full ISO 8601 time (`2026-12-31T12:00:00Z`).
A date without a time is the last second of that day (23:59:59), in the time zone of the application.
The database calculates `expires_at` with its own clock, as Rodauth does for its deadlines.

To change a page, put a template with the same name in the views directory of the application:
`api-keys.str`, `create-api-key.str`, `api-key-created.str`, or `revoke-api-key.str`.

## JSON API

With the `json` feature, the management routes accept and return JSON. All requests use `POST`.

Create an API key:

```sh
curl -X POST https://example.com/create-api-key \
  -H "Content-Type: application/json" -H "Authorization: <JWT>" \
  -d '{"api_key_name": "CI server", "password": "...", "api_key_scopes": ["projects:read"], "api_key_expires_at": "2026-12-31"}'
```

```json
{
  "api_key": "myapp_Qb4JPgNpNhcsdekspshofQVvGUcpchLRstT6HAu7EQS",
  "id": 1,
  "name": "CI server",
  "hint": "myapp_Qb4J",
  "scopes": ["projects:read"],
  "created_at": "2026-10-02T12:00:00+00:00",
  "last_use": null,
  "expires_at": "2026-12-31T23:59:59+00:00",
  "revoked_at": null,
  "status": "active",
  "success": "Your API key is ready. Copy it now. You cannot see it again."
}
```

- `POST /api-keys` returns `{"api_keys": [...]}`. Each item has the same fields, but no `api_key`.
- `POST /revoke-api-key` with `{"api_key_id": 1, "password": "..."}` returns `{"success": "The API key is revoked"}`.
- An error returns `{"error": "...", "field-error": ["<parameter>", "<message>"]}`.

The `api_key_scopes` parameter can also be a string with scopes separated by spaces.

## Internal requests

With the `internal_request` feature:

```ruby
result = App.rodauth.create_api_key(account_login: "user@example.com", api_key_name: "CI server", api_key_scopes: ["projects:read"])
result[:api_key] # => "myapp_..."

App.rodauth.api_keys(account_login: "user@example.com")
# => [{id: 1, name: "CI server", hint: "myapp_Qb4J", scopes: ["projects:read"], status: :active, ...}]

App.rodauth.revoke_api_key(account_login: "user@example.com", api_key_id: result[:id])
```

Internal requests do not ask for the password. An error raises `Rodauth::InternalRequestError`.

## Configuration reference

### Values

| Method | Default | Description |
|---|---|---|
| `api_key_prefix` | `"rak"` | The prefix of each API key. Letters and digits, with single underscores between them. |
| `api_key_secret_length` | `43` | The number of random letters and digits after the prefix (approximately 256 bits). |
| `api_key_hint_length` | `4` | The number of secret characters in the hint. |
| `api_key_realm` | `"api"` | The realm in the `WWW-Authenticate` header. |
| `api_key_authorization_regexp` | `/\ABearer\s+(<prefix>_[A-Za-z0-9]+)\s*\z/` | Finds the API key in the `Authorization` header. The first capture group must contain the API key. |
| `api_keys_limit` | `10` | The maximum number of active API keys for each account. `nil` removes the limit. |
| `api_key_name_max_length` | `100` | The maximum length of the name. |
| `api_key_scopes` | `[]` | The permitted scope names. If the list is empty, the feature does not use scopes. |
| `api_key_max_lifetime` | `nil` | The maximum lifetime in seconds. A value makes the expiration date necessary. |
| `api_key_last_use_update_interval` | `60` | The minimum number of seconds between two updates of `last_use`. |
| `revoke_api_keys_on_password_change?` | `false` | Revoke all API keys after a password change or a password reset. |
| `api_keys_table` | `:account_api_keys` | The table name. |
| `api_keys_*_column` | see migration | One method for each column: `id`, `account_id`, `name`, `digest`, `hint`, `scopes`, `created_at`, `last_use`, `expires_at`, `revoked_at`. |
| `api_key_name_param`, `api_key_expires_at_param`, `api_key_scopes_param`, `api_key_id_param` | `"api_key_name"`, ... | Parameter names. |
| `api_keys_route`, `create_api_key_route`, `revoke_api_key_route` | `"api-keys"`, ... | Route names. |
| `insufficient_api_key_scope_error_status` | `403` | The status for a missing scope. |
| `api_key_management_not_permitted_error_status` | `403` | The status for a management request with an API key. |

To accept the `Token` scheme too:

```ruby
api_key_authorization_regexp(/\A(?:Bearer|Token)\s+(myapp_[A-Za-z0-9]+)\s*\z/)
```

### Messages and labels

You can change each text with its configuration method, for example `invalid_api_key_message "API key not valid"`.
The texts:

- Messages: `invalid_api_key_message`, `api_key_required_message`, `insufficient_api_key_scope_message`, `api_key_management_not_permitted_message`, `invalid_api_key_name_message`, `invalid_api_key_expires_at_message`, `api_key_expires_at_required_message`, `api_key_expires_at_past_message`, `api_key_expires_at_too_late_message`, `invalid_api_key_scopes_message`, `api_key_scopes_required_message`, `api_keys_limit_message`, `invalid_api_key_id_message`, `no_active_api_keys_message`, `api_keys_empty_message`.
- Flash messages: `create_api_key_notice_flash`, `create_api_key_error_flash`, `revoke_api_key_notice_flash`, `revoke_api_key_error_flash`.
- Labels and buttons: the `*_label`, `*_link_text`, `*_button`, and `*_page_title` methods.

### Hooks

`before_api_keys_route`, `before_create_api_key_route`, `before_create_api_key`, `after_create_api_key`, `before_revoke_api_key_route`, `before_revoke_api_key`, `after_revoke_api_key`.

With the `audit_logging` feature, Rodauth logs the `create_api_key` and `revoke_api_key` actions.

### Methods that you can override

`generate_api_key`, `api_key_digest`, `api_key_digests`, `api_key_hint`, `api_key_from_request`, `api_key_insert_hash`, `create_api_key`, `revoke_api_key`, `revoke_all_api_keys`, `account_api_keys`, `valid_api_key_name?`, `valid_api_key_scopes?`, `parse_api_key_expires_at`, `update_api_key_last_use`, `api_key_created_response`, `api_key_authenticated?`, `api_key_scope?`, `require_api_key_authentication`, `require_api_key_scope`.

To add a column to each new row, override `api_key_insert_hash`:

```ruby
api_key_insert_hash do |*args|
  super(*args).merge(created_ip: request.ip)
end
```

## Security

- The database keeps the HMAC-SHA256 digest of the API key, not the API key. A copy of the database does not give the API keys without `hmac_secret`.
- During a rotation of `hmac_secret`, set `hmac_old_secret`. The feature accepts the old digest and writes the new digest at the next use of the API key.
- The feature does not write the API key to logs or to error messages.
- A closed account cannot use its API keys. `close_account` revokes them. If `close_account` calls `delete_account`, the feature removes the API key rows first.
- With the `jwt` feature, a response to an API key request does not contain a JWT. Such a JWT would authenticate the account without the API key.
- An API key cannot create, list, or revoke API keys.

### Remove old rows

The feature does not remove revoked or expired rows. To remove rows that are older than 90 days, use a command like this one:

```ruby
DB.extension :date_arithmetic
cutoff = Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, days: 90)
DB[:account_api_keys].where { (revoked_at < cutoff) | (expires_at < cutoff) }.delete
```

## Development

After you clone the repository, run `bin/setup` to install the dependencies.

- Run the tests and the linter: `bundle exec rake`
- Run the tests only: `bundle exec rake test`
- Run the linter only: `bundle exec rake standard`
- Start a console: `bin/console`

To release a new version, change the version number in `rodauth-api_keys.gemspec`. Then run `bundle exec rake release`.
This command makes a git tag for the version, pushes the commits and the tag, and pushes the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Send bug reports and pull requests on GitHub at https://github.com/dush/rodauth-api_keys.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
