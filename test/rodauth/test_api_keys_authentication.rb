# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysAuthentication < RodauthTestCase
  ROUTES = proc do |r|
    r.rodauth

    r.is "require-authentication" do
      rodauth.require_authentication
      "#{rodauth.session_value} #{rodauth.api_key_authenticated?} #{rodauth.current_api_key_id.inspect}"
    end

    r.is "require-api-key" do
      rodauth.require_api_key_authentication
      "#{rodauth.session_value} #{rodauth.current_api_key_id}"
    end

    r.is "scope", String do |scope|
      rodauth.require_api_key_scope(scope)
      "permitted #{scope}"
    end

    r.is "has-scope", String do |scope|
      rodauth.api_key_scope?(scope).to_s
    end

    r.is "clear-session" do
      rodauth.clear_session
      "cleared"
    end

    r.root { rodauth.session_value.to_s }
  end

  # Make an app and an account with an API key. Return the API key.
  # The features in the features argument come before api_keys.
  def setup_api_key(json: false, create: {}, features: [], &config)
    rodauth_app(json: json, route: ROUTES) do
      enable(*features, :api_keys)
      instance_exec(&config) if config
    end
    @account_id = create_account
    r = app.rodauth.allocate
    r.account_from_id(@account_id)
    api_key = r.create_api_key("test", **create)
    @api_key_id = r.created_api_key_id
    api_key
  end

  def api_key_row
    DB[:account_api_keys].where(id: @api_key_id).first
  end

  def bearer(api_key)
    {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}
  end

  def assert_invalid_api_key_response
    assert_equal 401, last_response.status
    assert_equal 'Bearer realm="api", error="invalid_token"', last_response["www-authenticate"]
    assert_equal "invalid API key", last_response.body
  end

  def test_valid_api_key_authenticates_request
    api_key = setup_api_key

    get "/require-authentication", {}, bearer(api_key)

    assert_equal 200, last_response.status
    assert_equal "#{@account_id} true #{@api_key_id}", last_response.body
  end

  def test_api_key_request_does_not_set_session_cookie
    api_key = setup_api_key

    get "/require-authentication", {}, bearer(api_key)

    assert_equal 200, last_response.status
    assert_nil last_response["set-cookie"]
    get "/"
    assert_equal "", last_response.body
  end

  def test_unknown_api_key_sends_401
    setup_api_key

    get "/require-authentication", {}, bearer("rak_#{"A" * 43}")

    assert_invalid_api_key_response
  end

  def test_invalid_api_key_does_not_use_cookie_session
    setup_api_key
    login

    get "/", {}, bearer("rak_#{"A" * 43}")

    assert_invalid_api_key_response
  end

  def test_revoked_api_key_sends_401
    api_key = setup_api_key
    DB[:account_api_keys].where(id: @api_key_id).update(revoked_at: Sequel::CURRENT_TIMESTAMP)

    get "/require-authentication", {}, bearer(api_key)

    assert_invalid_api_key_response
  end

  def test_expired_api_key_sends_401
    api_key = setup_api_key(create: {expires_in: -1})

    get "/require-authentication", {}, bearer(api_key)

    assert_invalid_api_key_response
  end

  def test_api_key_with_future_expiration_authenticates
    api_key = setup_api_key(create: {expires_in: 3600})

    get "/require-authentication", {}, bearer(api_key)

    assert_equal 200, last_response.status
  end

  def test_api_key_of_closed_account_sends_401
    api_key = setup_api_key { skip_status_checks? false }
    DB[:accounts].where(id: @account_id).update(status_id: 3)

    get "/require-authentication", {}, bearer(api_key)

    assert_invalid_api_key_response
  end

  def test_api_key_of_unverified_account_sends_401
    api_key = setup_api_key { skip_status_checks? false }
    DB[:accounts].where(id: @account_id).update(status_id: 1)

    get "/require-authentication", {}, bearer(api_key)

    assert_invalid_api_key_response
  end

  # The verify_account_grace_period feature lets an unverified account use a cookie session. It must not use an API key.
  def test_api_key_of_unverified_account_in_grace_period_sends_401
    api_key = setup_api_key(features: [:verify_account_grace_period])
    DB[:accounts].where(id: @account_id).update(status_id: 1)
    DB[:account_verification_keys].insert(id: @account_id, key: "key")

    get "/require-authentication", {}, bearer(api_key)

    assert_invalid_api_key_response
  end

  def test_other_authorization_values_are_ignored
    api_key = setup_api_key

    ["Basic #{api_key}", "Token #{api_key}", "Bearer other_#{"A" * 43}", api_key].each do |value|
      get "/", {}, {"HTTP_AUTHORIZATION" => value}
      assert_equal 200, last_response.status
      assert_equal "", last_response.body
    end
  end

  def test_other_authorization_values_use_cookie_session
    setup_api_key
    login

    get "/require-authentication", {}, {"HTTP_AUTHORIZATION" => "Basic Zm9vOmJhcg=="}

    assert_equal 200, last_response.status
    assert_equal "#{@account_id} false nil", last_response.body
  end

  def test_last_use_is_set_on_first_use
    api_key = setup_api_key

    get "/require-authentication", {}, bearer(api_key)

    refute_nil api_key_row[:last_use]
  end

  def test_last_use_update_skips_recent_use
    api_key = setup_api_key
    recent = Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 30)
    DB[:account_api_keys].where(id: @api_key_id).update(last_use: recent)
    before = api_key_row[:last_use]

    get "/require-authentication", {}, bearer(api_key)

    assert_equal before, api_key_row[:last_use]
  end

  def test_last_use_update_after_interval
    api_key = setup_api_key
    DB[:account_api_keys].where(id: @api_key_id).update(last_use: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 120))
    before = api_key_row[:last_use]

    get "/require-authentication", {}, bearer(api_key)

    assert_operator api_key_row[:last_use], :>, before
  end

  def test_last_use_updates_on_each_request_without_interval
    api_key = setup_api_key { api_key_last_use_update_interval nil }
    DB[:account_api_keys].where(id: @api_key_id).update(last_use: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 5))
    before = api_key_row[:last_use]

    get "/require-authentication", {}, bearer(api_key)

    assert_operator api_key_row[:last_use], :>, before
  end

  def test_api_key_from_old_hmac_secret_authenticates_and_gets_new_digest
    api_key = setup_api_key { hmac_secret "old-secret" }
    rodauth_app(route: ROUTES) do
      enable :api_keys
      hmac_secret "new-secret"
      hmac_old_secret "old-secret"
    end
    r = app.rodauth.allocate

    get "/require-authentication", {}, bearer(api_key)

    assert_equal 200, last_response.status
    assert_equal r.compute_hmac(api_key), api_key_row[:digest]
  end

  def test_api_key_from_old_hmac_secret_fails_without_hmac_old_secret
    api_key = setup_api_key { hmac_secret "old-secret" }
    rodauth_app(route: ROUTES) do
      enable :api_keys
      hmac_secret "new-secret"
    end

    get "/require-authentication", {}, bearer(api_key)

    assert_invalid_api_key_response
  end

  def test_require_api_key_authentication_accepts_api_key
    api_key = setup_api_key

    get "/require-api-key", {}, bearer(api_key)

    assert_equal 200, last_response.status
    assert_equal "#{@account_id} #{@api_key_id}", last_response.body
  end

  def test_require_api_key_authentication_refuses_cookie_session
    setup_api_key
    login

    get "/require-api-key"

    assert_equal 401, last_response.status
    assert_equal 'Bearer realm="api"', last_response["www-authenticate"]
    assert_equal "API key required", last_response.body
  end

  def test_api_key_realm_can_change
    setup_api_key { api_key_realm "my app" }

    get "/require-api-key"

    assert_equal 'Bearer realm="my app"', last_response["www-authenticate"]
  end

  def test_require_api_key_scope_permits_api_key_with_scope
    api_key = setup_api_key(create: {scopes: %w[read write]}) { api_key_scopes %w[read write admin] }

    get "/scope/write", {}, bearer(api_key)

    assert_equal 200, last_response.status
    assert_equal "permitted write", last_response.body
  end

  def test_require_api_key_scope_refuses_api_key_without_scope
    api_key = setup_api_key(create: {scopes: %w[read]}) { api_key_scopes %w[read write] }

    get "/scope/write", {}, bearer(api_key)

    assert_equal 403, last_response.status
    assert_equal 'Bearer realm="api", error="insufficient_scope", scope="write"', last_response["www-authenticate"]
    assert_equal "API key does not have the necessary scope", last_response.body
  end

  def test_api_key_without_scopes_has_no_scope
    api_key = setup_api_key { api_key_scopes %w[read] }

    get "/has-scope/read", {}, bearer(api_key)

    assert_equal "false", last_response.body
  end

  def test_require_api_key_scope_permits_cookie_session
    setup_api_key { api_key_scopes %w[read write] }
    login

    get "/scope/write"

    assert_equal 200, last_response.status
  end

  def test_require_api_key_scope_requires_authentication
    setup_api_key { api_key_scopes %w[read] }

    get "/scope/read"

    assert_equal 302, last_response.status
    get "/has-scope/read"
    assert_equal "false", last_response.body
  end

  def test_json_error_response
    setup_api_key(json: true)

    body = json_request("/require-authentication", {}, bearer("rak_#{"A" * 43}"))

    assert_equal 401, last_response.status
    assert_equal({"error" => "invalid API key"}, body)
    assert_equal "application/json", last_response["content-type"]
  end

  def test_clear_session_does_not_clear_cookie_session
    api_key = setup_api_key
    login

    get "/clear-session", {}, bearer(api_key)
    get "/"

    assert_equal @account_id.to_s, last_response.body
  end

  def test_api_key_counts_as_two_factor_authentication
    api_key = setup_api_key(features: [:two_factor_base]) do
      auth_class_eval do
        define_method(:two_factor_authentication_setup?) { true }
      end
    end

    get "/require-authentication", {}, bearer(api_key)
    assert_equal 200, last_response.status

    login
    get "/require-authentication"
    assert_equal 302, last_response.status
  end

  def test_two_factor_base_after_api_keys_raises_configuration_error
    error = assert_raises(Rodauth::ConfigurationError) do
      rodauth_object { enable :two_factor_base }
    end

    assert_equal "enable :api_keys after :two_factor_base and the features that use it", error.message
  end
end
