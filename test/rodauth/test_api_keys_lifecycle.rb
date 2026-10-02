# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysLifecycle < RodauthTestCase
  NEW_PASSWORD = "9876543210"

  # The features in the features argument come before api_keys.
  def setup_app(features: [], json: false, &config)
    rodauth_app(json: json) do
      enable(*features, :api_keys)
      instance_exec(&config) if config
    end
    @account_id = create_account
  end

  def create_key(account_id: @account_id, **options)
    r = app.rodauth.allocate
    r.account_from_id(account_id)
    api_key = r.create_api_key("key", **options)
    [r.created_api_key_id, api_key]
  end

  def revoked_at(id)
    DB[:account_api_keys].where(id: id).get(:revoked_at)
  end

  def bearer(api_key)
    {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}
  end

  def test_revoke_all_api_keys
    setup_app
    other_id = create_account(login: "bar@example.com")
    id1, = create_key
    id2, = create_key
    old_id, = create_key
    other_key_id, = create_key(account_id: other_id)
    DB[:account_api_keys].where(id: old_id).update(revoked_at: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, days: 1))
    old_revoked_at = revoked_at(old_id)
    r = app.rodauth.allocate
    r.account_from_id(@account_id)

    assert_equal 2, r.revoke_all_api_keys
    refute_nil revoked_at(id1)
    refute_nil revoked_at(id2)
    assert_equal old_revoked_at, revoked_at(old_id)
    assert_nil revoked_at(other_key_id)
  end

  def test_close_account_revokes_api_keys
    setup_app(features: [:close_account])
    id, api_key = create_key
    login

    post "/close-account", "password" => PASSWORD

    assert_equal 302, last_response.status
    assert_equal 3, DB[:accounts].where(id: @account_id).get(:status_id)
    refute_nil revoked_at(id)
    clear_cookies
    get "/require-authentication", {}, bearer(api_key)
    assert_equal 401, last_response.status
  end

  def test_close_account_removes_api_keys_before_it_deletes_account
    setup_app(features: [:close_account]) { delete_account_on_close? true }
    create_key
    login

    post "/close-account", "password" => PASSWORD

    assert_equal 302, last_response.status
    assert_equal 0, DB[:accounts].where(id: @account_id).count
    assert_equal 0, DB[:account_api_keys].where(account_id: @account_id).count
  end

  def test_close_account_after_api_keys_also_revokes_api_keys
    rodauth_app do
      enable :api_keys, :close_account
    end
    @account_id = create_account
    id, = create_key
    login

    post "/close-account", "password" => PASSWORD

    refute_nil revoked_at(id)
  end

  def test_password_change_keeps_api_keys_by_default
    setup_app(features: [:change_password])
    id, api_key = create_key
    login

    post "/change-password", "password" => PASSWORD, "new-password" => NEW_PASSWORD, "password-confirm" => NEW_PASSWORD

    assert_equal 302, last_response.status
    assert_nil revoked_at(id)
    get "/require-authentication", {}, bearer(api_key)
    assert_equal 200, last_response.status
  end

  def test_password_change_revokes_api_keys_with_setting
    setup_app(features: [:change_password]) { revoke_api_keys_on_password_change? true }
    id, = create_key
    login

    post "/change-password", "password" => PASSWORD, "new-password" => NEW_PASSWORD, "password-confirm" => NEW_PASSWORD

    assert_equal 302, last_response.status
    refute_nil revoked_at(id)
  end

  def test_clear_tokens_reasons
    setup_app { revoke_api_keys_on_password_change? true }
    r = app.rodauth.allocate
    r.account_from_id(@account_id)

    {change_login: false, verify_account: false, unlock_account: false, reset_password: true}.each do |reason, revoked|
      id, = create_key
      r.clear_tokens(reason)
      assert_equal revoked, !revoked_at(id).nil?, "reason #{reason}"
    end
  end

  def test_jwt_does_not_read_api_key
    setup_app(features: [:jwt], json: true) { jwt_secret "jwt-secret" }
    _, api_key = create_key

    get "/require-authentication", {}, bearer(api_key).merge("CONTENT_TYPE" => "application/json")

    assert_equal 200, last_response.status
    assert_equal @account_id.to_s, last_response.body
  end

  def test_jwt_still_works_with_api_keys
    setup_app(features: [:jwt], json: true) { jwt_secret "jwt-secret" }

    json_request("/login", login: LOGIN, password: PASSWORD)
    jwt = last_response["authorization"]
    refute_nil jwt
    clear_cookies
    get "/require-authentication", {}, {"HTTP_AUTHORIZATION" => "Bearer #{jwt}", "CONTENT_TYPE" => "application/json"}

    assert_equal 200, last_response.status
    assert_equal @account_id.to_s, last_response.body
  end

  def test_jwt_is_not_sent_for_api_key_request
    setup_app(features: [:jwt], json: true) { jwt_secret "jwt-secret" }
    _, api_key = create_key

    # The json feature sends a JWT with each JSON response. The api-keys route refuses an API key with a JSON response.
    body = json_request("/api-keys", {}, bearer(api_key))

    assert_equal 403, last_response.status
    assert_equal "an API key cannot manage API keys", body["error"]
    assert_nil last_response["authorization"]
  end

  def test_jwt_does_not_make_api_key_request_a_json_request
    setup_app(features: [:jwt], json: true) { jwt_secret "jwt-secret" }
    _, api_key = create_key

    # The jwt feature uses JSON when jwt_token returns a value. An API key is not a JWT.
    get "/api-keys", {}, bearer(api_key)

    assert_equal 403, last_response.status
    assert_equal "an API key cannot manage API keys", last_response.body
    assert_equal "text/plain", last_response["content-type"]
  end

  def test_jwt_is_sent_for_invalid_api_key_without_account
    setup_app(features: [:jwt], json: true) { jwt_secret "jwt-secret" }

    json_request("/api-keys", {}, bearer("rak_#{"A" * 43}"))

    assert_equal 401, last_response.status
    jwt = last_response["authorization"]
    refute_nil jwt
    assert_equal({}, JWT.decode(jwt, "jwt-secret", true, algorithm: "HS256").first)
  end

  def test_jwt_after_api_keys_raises_configuration_error
    error = assert_raises(Rodauth::ConfigurationError) do
      rodauth_app(json: true) do
        enable :api_keys, :jwt
        jwt_secret "jwt-secret"
      end
    end

    assert_equal "enable :api_keys after :jwt and the features that use it", error.message
  end
end
