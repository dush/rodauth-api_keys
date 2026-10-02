# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysCreateRoute < RodauthTestCase
  API_KEY_REGEXP = /rak_[A-Za-z0-9]{43}/

  def setup_app(json: false, &config)
    rodauth_app(json: json) do
      enable :api_keys
      instance_exec(&config) if config
    end
    @account_id = create_account
  end

  def create_params(params = {})
    {"api_key_name" => "CI server", "password" => PASSWORD}.merge(params)
  end

  def api_key_rows
    DB[:account_api_keys].where(account_id: @account_id)
  end

  def date_after(days)
    (Date.today + days).iso8601
  end

  def assert_field_error(status, message)
    assert_equal status, last_response.status
    assert_includes last_response.body, "Unable to create the API key"
    assert_includes last_response.body, message
    assert_equal 0, api_key_rows.count
  end

  def test_create_page_requires_login
    setup_app

    get "/create-api-key"

    assert_equal 302, last_response.status
    assert_equal "/login", last_response["location"]
  end

  def test_create_page_shows_form
    setup_app
    login

    get "/create-api-key"

    assert_equal 200, last_response.status
    assert_includes last_response.body, 'name="api_key_name"'
    assert_includes last_response.body, 'type="date"'
    assert_includes last_response.body, 'name="password"'
    refute_includes last_response.body, "api_key_scopes"
  end

  def test_create_shows_api_key_one_time
    setup_app
    login

    post "/create-api-key", create_params

    assert_equal 200, last_response.status
    assert_equal "no-store", last_response["cache-control"]
    assert_includes last_response.body, "Your API key is ready. Copy it now. You cannot see it again."
    api_key = last_response.body[API_KEY_REGEXP]
    row = api_key_rows.first
    assert_equal "CI server", row[:name]
    assert_equal app.rodauth.allocate.api_key_digest(api_key), row[:digest]

    get "/create-api-key"
    refute_includes last_response.body, api_key
  end

  def test_created_api_key_authenticates
    setup_app
    login
    post "/create-api-key", create_params
    api_key = last_response.body[API_KEY_REGEXP]
    clear_cookies

    get "/require-authentication", {}, {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}

    assert_equal 200, last_response.status
    assert_equal @account_id.to_s, last_response.body
  end

  def test_create_refuses_wrong_password
    setup_app
    login

    post "/create-api-key", create_params("password" => "wrong")

    assert_field_error 401, "invalid password"
  end

  def test_create_without_password_for_account_without_password
    setup_app
    login
    DB[:account_password_hashes].where(id: @account_id).delete

    get "/create-api-key"
    refute_includes last_response.body, 'name="password"'
    post "/create-api-key", create_params.except("password")

    assert_equal 200, last_response.status
    assert_equal 1, api_key_rows.count
  end

  def test_create_refuses_empty_name
    setup_app
    login

    post "/create-api-key", create_params("api_key_name" => "   ")

    assert_field_error 422, "invalid name"
  end

  def test_create_refuses_long_name
    setup_app { api_key_name_max_length 10 }
    login

    post "/create-api-key", create_params("api_key_name" => "A" * 11)

    assert_field_error 422, "invalid name"
  end

  def test_create_strips_name
    setup_app
    login

    post "/create-api-key", create_params("api_key_name" => "  CI server  ")

    assert_equal "CI server", api_key_rows.get(:name)
  end

  def test_create_page_shows_scopes
    setup_app { api_key_scopes %w[read write] }
    login

    get "/create-api-key"

    assert_includes last_response.body, 'name="api_key_scopes[]"'
    assert_includes last_response.body, 'value="read"'
    assert_includes last_response.body, 'value="write"'
  end

  def test_create_keeps_selected_scopes
    setup_app { api_key_scopes %w[read write admin] }
    login

    post "/create-api-key", create_params("api_key_scopes" => %w[read write])

    assert_equal 200, last_response.status
    assert_equal "read write", api_key_rows.get(:scopes)
  end

  def test_create_requires_scope_when_scopes_are_configured
    setup_app { api_key_scopes %w[read write] }
    login

    post "/create-api-key", create_params

    assert_field_error 422, "select one or more scopes"
  end

  def test_create_refuses_unknown_scope
    setup_app { api_key_scopes %w[read write] }
    login

    post "/create-api-key", create_params("api_key_scopes" => %w[read admin])

    assert_field_error 422, "invalid scope"
  end

  def test_create_refuses_scope_when_no_scopes_are_configured
    setup_app
    login

    post "/create-api-key", create_params("api_key_scopes" => %w[read])

    # The form has no scope field, so only the error flash shows the error.
    assert_field_error 422, "Unable to create the API key"
  end

  def test_create_form_keeps_selected_scopes_after_error
    setup_app { api_key_scopes %w[read write] }
    login

    post "/create-api-key", create_params("api_key_name" => "", "api_key_scopes" => %w[write])

    assert_includes last_response.body, 'checked="checked"'
    assert_match(/checked="checked"[^>]*value="write"|value="write"[^>]*checked="checked"/, last_response.body)
  end

  def test_create_with_expiration_date
    setup_app
    login

    post "/create-api-key", create_params("api_key_expires_at" => date_after(10))

    assert_equal 200, last_response.status
    ds = api_key_rows
    assert_equal 1, ds.where { expires_at > Sequel.date_add(Sequel::CURRENT_TIMESTAMP, days: 9) }.count
    assert_equal 1, ds.where { expires_at < Sequel.date_add(Sequel::CURRENT_TIMESTAMP, days: 11) }.count
  end

  def test_create_with_iso8601_time
    setup_app
    login

    post "/create-api-key", create_params("api_key_expires_at" => (Time.now + 7200).utc.iso8601)

    assert_equal 200, last_response.status
    ds = api_key_rows
    assert_equal 1, ds.where { expires_at > Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: 7100) }.count
    assert_equal 1, ds.where { expires_at < Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: 7300) }.count
  end

  def test_create_refuses_invalid_expiration_date
    setup_app
    login

    ["2030-02-30", "tomorrow", "2030-1-1"].each do |value|
      post "/create-api-key", create_params("api_key_expires_at" => value)
      assert_field_error 422, "invalid expiration date"
    end
  end

  def test_create_refuses_past_expiration_date
    setup_app
    login

    post "/create-api-key", create_params("api_key_expires_at" => date_after(-1))

    assert_field_error 422, "expiration date must be in the future"
  end

  def test_create_refuses_expiration_after_max_lifetime
    setup_app { api_key_max_lifetime 86400 * 30 }
    login

    post "/create-api-key", create_params("api_key_expires_at" => date_after(60))

    assert_field_error 422, "expiration date is too late"
  end

  def test_create_requires_expiration_with_max_lifetime
    setup_app { api_key_max_lifetime 86400 * 30 }
    login

    get "/create-api-key"
    assert_match(/required="required"[^>]*type="date"/, last_response.body)
    post "/create-api-key", create_params

    assert_field_error 422, "expiration date is necessary"
  end

  def test_create_with_expiration_before_max_lifetime
    setup_app { api_key_max_lifetime 86400 * 30 }
    login

    post "/create-api-key", create_params("api_key_expires_at" => date_after(10))

    assert_equal 200, last_response.status
    assert_equal 1, api_key_rows.count
  end

  def test_create_refuses_api_key_over_limit
    setup_app { api_keys_limit 2 }
    login
    2.times { post "/create-api-key", create_params }

    post "/create-api-key", create_params

    assert_equal 422, last_response.status
    assert_includes last_response.body, "maximum number of active API keys"
    assert_equal 2, api_key_rows.count
  end

  def test_limit_does_not_count_revoked_and_expired_api_keys
    setup_app { api_keys_limit 2 }
    login
    insert_api_key(@account_id, revoked_at: Sequel::CURRENT_TIMESTAMP)
    insert_api_key(@account_id, expires_at: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, days: 1))
    insert_api_key(@account_id)

    post "/create-api-key", create_params

    assert_equal 200, last_response.status
    assert_equal 4, api_key_rows.count
  end

  def test_no_limit_when_limit_is_nil
    setup_app { api_keys_limit nil }
    login
    11.times { post "/create-api-key", create_params }

    assert_equal 11, api_key_rows.count
  end

  def test_api_key_cannot_create_api_key
    setup_app
    r = app.rodauth.allocate
    r.account_from_id(@account_id)
    api_key = r.create_api_key("first")

    post "/create-api-key", create_params, {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}

    assert_equal 403, last_response.status
    assert_equal "an API key cannot use this route", last_response.body
    assert_equal 1, api_key_rows.count
  end

  def test_create_hooks
    calls = []
    setup_app do
      before_create_api_key { calls << [:before, created_api_key_id] }
      after_create_api_key { calls << [:after, created_api_key_id] }
    end
    login

    post "/create-api-key", create_params

    assert_equal [[:before, nil], [:after, api_key_rows.get(:id)]], calls
  end

  def test_templates_can_be_precompiled
    app = Class.new(Roda)
    app.plugin :render
    app.plugin(:rodauth, csrf: false) do
      enable :login, :api_keys
      hmac_secret "test-hmac-secret"
      already_logged_in { request.redirect "/" }
    end

    # Rodauth reads each template in loaded_templates. A missing template raises an error.
    app.precompile_rodauth_templates
    pass
  end

  def test_parse_api_key_expires_at
    r = rodauth_object

    assert_equal Time.new(2030, 12, 31, 23, 59, 59), r.parse_api_key_expires_at("2030-12-31")
    assert_equal Time.utc(2030, 12, 31, 12), r.parse_api_key_expires_at("2030-12-31T12:00:00Z")
    assert_nil r.parse_api_key_expires_at("2030-02-30")
    assert_nil r.parse_api_key_expires_at("")
  end

  def test_json_create
    setup_app(json: true) { api_key_scopes %w[read write] }
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/create-api-key", "api_key_name" => "CI server", "password" => PASSWORD,
      "api_key_scopes" => %w[read], "api_key_expires_at" => date_after(10))

    assert_equal 200, last_response.status
    assert_equal "no-store", last_response["cache-control"]
    assert_match(/\A#{API_KEY_REGEXP}\z/o, body["api_key"])
    assert_equal api_key_rows.get(:id), body["id"]
    assert_equal "active", body["status"]
    refute_nil Time.iso8601(body["created_at"])
    assert_nil body["last_use"]
    assert_nil body["revoked_at"]
    assert_equal "CI server", body["name"]
    assert_equal body["api_key"][0, 8], body["hint"]
    assert_equal ["read"], body["scopes"]
    assert_operator Time.iso8601(body["expires_at"]), :>, Time.now + 86400 * 9
    assert_equal "Your API key is ready. Copy it now. You cannot see it again.", body["success"]
  end

  def test_json_create_without_expiration
    setup_app(json: true)
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/create-api-key", "api_key_name" => "CI server", "password" => PASSWORD)

    assert_nil body["expires_at"]
    assert_equal [], body["scopes"]
  end

  def test_json_create_scopes_as_string
    setup_app(json: true) { api_key_scopes %w[read write] }
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/create-api-key", "api_key_name" => "CI server", "password" => PASSWORD, "api_key_scopes" => "read write")

    assert_equal %w[read write], body["scopes"]
  end

  def test_json_create_error
    setup_app(json: true)
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/create-api-key", "api_key_name" => "", "password" => PASSWORD)

    assert_equal 422, last_response.status
    assert_equal "Unable to create the API key", body["error"]
    assert_equal ["api_key_name", "invalid name"], body["field-error"]
  end

  def test_json_create_refuses_non_string_scopes
    setup_app(json: true) { api_key_scopes %w[read] }
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/create-api-key", "api_key_name" => "CI", "password" => PASSWORD, "api_key_scopes" => [1])

    assert_equal ["api_key_scopes", "invalid scope"], body["field-error"]
  end
end
