# AGENTS.md

This file gives instructions to AI agents that work on this repository.

## Project

`rodauth-api_keys` is a Ruby gem. It adds an `api_keys` feature to
[Rodauth](https://github.com/jeremyevans/rodauth).

The feature lets an account create, list, and revoke API keys. A client
sends an API key in a request. Rodauth uses the key to authenticate the
request as the account that owns the key.

The project is new. Most of the code does not exist yet.

## Language rule: ASD-STE100

Write all text in ASD-STE100 Simplified Technical English (STE). See
<https://en.wikipedia.org/wiki/Simplified_Technical_English>.

This rule applies to:

- Code comments.
- Identifiers (method names, configuration names, column names).
- Error messages, flash messages, and log messages.
- Documentation (`README.md`, `doc/`, `CHANGELOG.md`, this file).
- Commit messages and pull request descriptions.

Obey these rules:

1. Use the active voice.
2. Use simple tenses: present, past, future, or imperative.
3. Write one instruction in one sentence.
4. Write a maximum of 20 words in an instruction sentence.
5. Write a maximum of 25 words in a descriptive sentence.
6. Do not use semicolons.
7. Do not use phrasal verbs. Write "remove", not "take out". Write "start", not "spin up".
8. Use a verb for an action. Write "check the key", not "perform a check of the key".
9. Use one word for one meaning. Use the same word every time.
10. Do not stack more than three nouns.
11. Use a list for three or more steps or conditions.
12. Do not use marketing words such as "seamless", "robust", or "powerful".

Use these terms. Do not use synonyms for them:

| Term | Meaning |
|---|---|
| account | The Rodauth account that owns an API key. Do not write "user" or "owner". |
| API key | The secret value that a client sends. Do not write "token" or "secret". |
| key prefix | The public label at the start of an API key, for example `rak`. It is the same for all API keys of an application. |
| key hint | The key prefix and the first characters of the secret. The list page shows it. |
| key digest | The HMAC of the full API key. The database keeps this value, not the API key. |
| revoke | Make an API key not valid. Set `revoked_at`. Do not write "delete", "disable", or "invalidate". |
| expire | An API key becomes not valid after a set time. |

Add a new term to this table before you use it in code or docs.

## Rodauth feature conventions

Follow the conventions of the features in the Rodauth source.
Read `lib/rodauth/features/*.rb` in Rodauth before you write a new feature method.

- Put the feature in `lib/rodauth/features/api_keys.rb`.
  Rodauth loads features from the path `rodauth/features/<name>`.
- Define the feature with `Rodauth::Feature.define(:api_keys, :ApiKeys)`.
- Declare dependencies with `depends`.
- Make each setting configurable. Use `auth_value_method` for values.
  Use `auth_methods` for methods. A method in `auth_methods` can be private.
  Do not use `auth_private_methods`, because it needs a method with the name `_<name>`.
- Call `uses_instance_variables` one time only, with all instance variables. A second call replaces the first list.
- Use the Rodauth prefixes for names: `api_key_`, `api_keys_`.
- Use the Rodauth helpers for routes, templates, buttons, flash messages, and redirects.
  Examples: `route`, `view`, `translate`, `set_notice_flash`, `set_redirect_error_flash`.
- Use Sequel for all database access. Use `db` and `ds` from Rodauth.
- Supply the hooks `before_*` and `after_*` for each action.
- Do not add the files `lib/rodauth/api_keys.rb` or `lib/rodauth/api_keys/version.rb`.
  `Feature.define` sets the constant `Rodauth::ApiKeys` to the feature module.
  A second `Rodauth::ApiKeys` module causes a conflict.
- Set the gem version in `rodauth-api_keys.gemspec` only.
- Put templates in `templates/`. Add each template to `loaded_templates`.
  The `template_path` override finds them. An application template with the same name has priority.
- In a template, escape each value from the database or the request with `h`.
- A route block must halt the request on success, for example with a redirect or `return_response`.
  `catch_error` ignores the value of its block.
- In an internal request (`internal_request?`), return data with `_return_from_internal_request`.
- Do not compare database times with `Time.now` in Ruby. Let the database compare with `Sequel::CURRENT_TIMESTAMP`.
  To write a time, use `Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: n)`.

### Feature order

This feature overrides methods of `two_factor_base`, `jwt`, `active_sessions`, and `single_session`. These overrides work only when `api_keys` comes later in the `enable` list.
`post_configure` raises `Rodauth::ConfigurationError` if the order is wrong.
If you override a method of another feature, add that feature to the check in `post_configure`.
Use `super if defined?(super)` in hooks such as `after_close_account`. Then the order is not important for them.

## Security rules

An API key is a credential. Obey these rules:

1. Generate the secret part with `SecureRandom`. Use a minimum of 32 bytes.
2. Show the full API key to the account one time only, when Rodauth creates it.
3. Do not keep the full API key in the database. Keep the key digest and the key hint.
4. Calculate the key digest with HMAC. Use `hmac_secret` from Rodauth.
5. Find the database row by the key digest. If you must compare two secrets, use `timing_safe_eql?`.
6. Do not write an API key to logs, error messages, or exceptions.
7. Check that the API key is not revoked and not expired before you accept it.
8. Check that the account is open (not closed and not unverified) before you accept an API key.

## Database

- Supply a Sequel migration for the API keys table in the docs or in `test/`.
- Use a foreign key from the API keys table to the accounts table.
- Add a unique index on the key digest. Rodauth uses the key digest to find the database row.

## Development

- Ruby version: 3.3 or later.
- Install dependencies: `bin/setup`.
- Run tests and lint: `bundle exec rake`.
- Run tests only: `bundle exec rake test`.
- Run lint only: `bundle exec rake standard`.
- Fix lint errors: `bundle exec standardrb --fix`.

Obey these rules:

1. Run `bundle exec rake` before you finish a task. All tests and lint checks must pass.
2. Write tests with Minitest.
3. Test the feature in a Roda app with Rodauth, Sequel, and an SQLite in-memory database.
   Use the helpers in `test/test_helper.rb`: `rodauth_app`, `rodauth_object`, `create_account`, `login`, `json_request`, and `insert_api_key`.
   Put the tests in `test/rodauth/test_api_keys_<topic>.rb`.
   For a security fix, remove the fix for a short time and make sure that its test fails.
4. Write a test for each new configuration method and each route.
5. Write a test for each security rule in this file.
6. Update `README.md` when you add or change a configuration method.
7. Do not add a runtime dependency other than `rodauth` without approval from a maintainer.

## Commits

- Write the subject line in the imperative mood. Example: "Add route to revoke API keys".
- Write a maximum of 72 characters in the subject line.
- Make one logical change in one commit.
