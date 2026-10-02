# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysInternalRequest < RodauthTestCase
  def setup_app(&config)
    rodauth_app do
      enable :api_keys, :internal_request
      domain "example.com"
      instance_exec(&config) if config
    end
    @account_id = create_account
  end

  def rodauth
    app.rodauth
  end

  def test_create_api_key
    setup_app { api_key_scopes %w[read write] }

    result = rodauth.create_api_key(account_login: LOGIN, api_key_name: "CI", api_key_scopes: %w[read], api_key_expires_at: (Date.today + 10).iso8601)

    assert_match(/\Arak_[A-Za-z0-9]{43}\z/, result[:api_key])
    row = DB[:account_api_keys].where(id: result[:id]).first
    assert_equal @account_id, row[:account_id]
    assert_equal "CI", result[:name]
    assert_equal result[:api_key][0, 8], result[:hint]
    assert_equal ["read"], result[:scopes]
    assert_equal :active, result[:status]
    assert_kind_of Time, result[:expires_at]
    assert_equal rodauth.allocate.api_key_digest(result[:api_key]), row[:digest]
  end

  def test_create_api_key_does_not_require_password
    setup_app

    result = rodauth.create_api_key(account_id: @account_id, api_key_name: "CI")

    refute_nil result[:api_key]
  end

  def test_create_api_key_error
    setup_app

    error = assert_raises(Rodauth::InternalRequestError) do
      rodauth.create_api_key(account_id: @account_id, api_key_name: "")
    end

    assert_equal :invalid_api_key_name, error.reason
    assert_equal({"api_key_name" => "invalid name"}, error.field_errors)
    assert_equal 0, DB[:account_api_keys].count
  end

  def test_create_api_key_limit
    setup_app { api_keys_limit 1 }
    rodauth.create_api_key(account_id: @account_id, api_key_name: "first")

    error = assert_raises(Rodauth::InternalRequestError) do
      rodauth.create_api_key(account_id: @account_id, api_key_name: "second")
    end

    assert_equal :api_keys_limit, error.reason
  end

  def test_create_api_key_requires_account
    setup_app

    assert_raises(Rodauth::InternalRequestError) do
      rodauth.create_api_key(account_login: "unknown@example.com", api_key_name: "CI")
    end
  end

  def test_api_keys
    setup_app
    first = rodauth.create_api_key(account_id: @account_id, api_key_name: "first")
    second = rodauth.create_api_key(account_id: @account_id, api_key_name: "second")

    result = rodauth.api_keys(account_login: LOGIN)

    assert_equal [second[:id], first[:id]], result.map { |api_key| api_key[:id] }
    assert_equal %w[second first], result.map { |api_key| api_key[:name] }
    assert_equal [:active, :active], result.map { |api_key| api_key[:status] }
    refute(result.any? { |api_key| api_key.key?(:api_key) })
  end

  def test_revoke_api_key
    setup_app
    created = rodauth.create_api_key(account_id: @account_id, api_key_name: "CI")

    assert_nil rodauth.revoke_api_key(account_id: @account_id, api_key_id: created[:id])

    assert_equal :revoked, rodauth.api_keys(account_id: @account_id).first[:status]
    get "/require-authentication", {}, {"HTTP_AUTHORIZATION" => "Bearer #{created[:api_key]}"}
    assert_equal 401, last_response.status
  end

  def test_revoke_api_key_error
    setup_app
    other_id = create_account(login: "bar@example.com")
    created = rodauth.create_api_key(account_id: other_id, api_key_name: "CI")

    error = assert_raises(Rodauth::InternalRequestError) do
      rodauth.revoke_api_key(account_id: @account_id, api_key_id: created[:id])
    end

    assert_equal :invalid_api_key_id, error.reason
    assert_equal :active, rodauth.api_keys(account_id: other_id).first[:status]
  end
end
