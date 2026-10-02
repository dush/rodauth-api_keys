# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysListRevoke < RodauthTestCase
  def setup_app(json: false, &config)
    rodauth_app(json: json) do
      enable :api_keys
      instance_exec(&config) if config
    end
    @account_id = create_account
  end

  # Create an API key for the account. Return [id, api_key].
  def create_key(name = "key", account_id: @account_id, **options)
    r = app.rodauth.allocate
    r.account_from_id(account_id)
    api_key = r.create_api_key(name, **options)
    [r.created_api_key_id, api_key]
  end

  def revoked_at(id)
    DB[:account_api_keys].where(id: id).get(:revoked_at)
  end

  def test_api_keys_page_requires_login
    setup_app

    get "/api-keys"

    assert_equal 302, last_response.status
    assert_equal "/login", last_response["location"]
  end

  def test_api_keys_page_without_api_keys
    setup_app
    login

    get "/api-keys"

    assert_equal 200, last_response.status
    assert_includes last_response.body, "There are no API keys."
    assert_includes last_response.body, 'href="/create-api-key"'
    refute_includes last_response.body, 'href="/revoke-api-key"'
  end

  def test_api_keys_page_lists_api_keys_of_account
    setup_app
    other_id = create_account(login: "bar@example.com")
    active_id, api_key = create_key("active key")
    revoked_id, = create_key("revoked key")
    expired_id, = create_key("expired key", expires_in: -1)
    create_key("other account key", account_id: other_id)
    DB[:account_api_keys].where(id: revoked_id).update(revoked_at: Sequel::CURRENT_TIMESTAMP)
    login

    get "/api-keys"

    body = last_response.body
    assert_equal 200, last_response.status
    assert_includes body, "active key"
    assert_includes body, "<code>#{api_key[0, 8]}&hellip;</code>"
    refute_includes body, api_key
    refute_includes body, "other account key"
    assert_match(/id="api-key-#{active_id}" class="api-key-active".*Active/, body)
    assert_match(/id="api-key-#{revoked_id}" class="api-key-revoked".*Revoked/, body)
    assert_match(/id="api-key-#{expired_id}" class="api-key-expired".*Expired/, body)
    assert_operator body.index("api-key-#{expired_id}"), :<, body.index("api-key-#{active_id}")
    assert_includes body, 'href="/revoke-api-key"'
    refute_includes body, "<th>Scopes</th>"
  end

  def test_api_keys_page_shows_scopes
    setup_app { api_key_scopes %w[read write] }
    create_key(scopes: %w[read write])
    login

    get "/api-keys"

    assert_includes last_response.body, "<th>Scopes</th>"
    assert_includes last_response.body, "<td>read write</td>"
  end

  def test_api_keys_page_escapes_name
    setup_app
    create_key("<script>")
    login

    get "/api-keys"

    refute_includes last_response.body, "<script>"
    assert_includes last_response.body, "&lt;script&gt;"
  end

  def test_account_api_keys
    setup_app
    id, api_key = create_key("CI", expires_in: 3600)
    DB[:account_api_keys].where(id: id).update(last_use: Sequel::CURRENT_TIMESTAMP)
    r = app.rodauth.allocate
    r.account_from_id(@account_id)

    item = r.account_api_keys.first

    assert_equal id, item[:id]
    assert_equal "CI", item[:name]
    assert_equal api_key[0, 8], item[:hint]
    assert_equal [], item[:scopes]
    assert_equal :active, item[:status]
    assert_kind_of Time, item[:created_at]
    assert_kind_of Time, item[:last_use]
    assert_kind_of Time, item[:expires_at]
    assert_nil item[:revoked_at]
  end

  def test_json_api_keys
    setup_app(json: true) { api_key_scopes %w[read] }
    id, api_key = create_key("CI", scopes: %w[read])
    revoked_id, = create_key("old")
    DB[:account_api_keys].where(id: revoked_id).update(revoked_at: Sequel::CURRENT_TIMESTAMP)
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/api-keys")

    assert_equal 200, last_response.status
    revoked, active = body["api_keys"]
    assert_equal id, active["id"]
    assert_equal "CI", active["name"]
    assert_equal api_key[0, 8], active["hint"]
    assert_equal ["read"], active["scopes"]
    assert_equal "active", active["status"]
    assert_nil active["expires_at"]
    assert_nil active["revoked_at"]
    refute_nil Time.iso8601(active["created_at"])
    assert_equal "revoked", revoked["status"]
    refute_nil Time.iso8601(revoked["revoked_at"])
    refute_includes last_response.body, "digest"
    refute_includes last_response.body, api_key
  end

  def test_api_key_cannot_list_api_keys
    setup_app
    _, api_key = create_key

    get "/api-keys", {}, {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}

    assert_equal 403, last_response.status
  end

  def test_revoke_page_lists_only_active_api_keys
    setup_app
    active_id, = create_key("active key")
    revoked_id, = create_key("revoked key")
    DB[:account_api_keys].where(id: revoked_id).update(revoked_at: Sequel::CURRENT_TIMESTAMP)
    login

    get "/revoke-api-key"

    assert_equal 200, last_response.status
    assert_includes last_response.body, "id=\"api-key-id-#{active_id}\""
    refute_includes last_response.body, "revoked key"
    assert_includes last_response.body, 'name="password"'
  end

  def test_revoke_page_without_active_api_keys
    setup_app
    login

    get "/revoke-api-key"

    assert_includes last_response.body, "There are no active API keys."
    refute_includes last_response.body, "<form"
  end

  def test_revoke_api_key
    setup_app
    id, api_key = create_key
    login

    post "/revoke-api-key", "api_key_id" => id.to_s, "password" => PASSWORD

    assert_equal 302, last_response.status
    assert_equal "/api-keys", last_response["location"]
    refute_nil revoked_at(id)
    follow_redirect!
    assert_includes last_response.body, "The API key is revoked"
    assert_includes last_response.body, "Revoked"

    clear_cookies
    get "/require-authentication", {}, {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}
    assert_equal 401, last_response.status
  end

  def test_revoke_keeps_the_row
    setup_app
    id, = create_key
    login

    post "/revoke-api-key", "api_key_id" => id.to_s, "password" => PASSWORD

    assert_equal 1, DB[:account_api_keys].where(id: id).count
  end

  def test_revoke_refuses_wrong_password
    setup_app
    id, = create_key
    login

    post "/revoke-api-key", "api_key_id" => id.to_s, "password" => "wrong"

    assert_equal 401, last_response.status
    assert_includes last_response.body, "Unable to revoke the API key"
    assert_includes last_response.body, "invalid password"
    assert_nil revoked_at(id)
  end

  def test_revoke_without_password_for_account_without_password
    setup_app
    id, = create_key
    login
    DB[:account_password_hashes].where(id: @account_id).delete

    post "/revoke-api-key", "api_key_id" => id.to_s

    assert_equal 302, last_response.status
    refute_nil revoked_at(id)
  end

  def test_revoke_requires_api_key_id
    setup_app
    create_key
    login

    post "/revoke-api-key", "password" => PASSWORD

    assert_equal 422, last_response.status
    assert_includes last_response.body, "select an active API key"
  end

  def test_revoke_refuses_api_key_of_other_account
    setup_app
    other_id = create_account(login: "bar@example.com")
    create_key
    other_key_id, = create_key(account_id: other_id)
    login

    post "/revoke-api-key", "api_key_id" => other_key_id.to_s, "password" => PASSWORD

    assert_equal 422, last_response.status
    assert_includes last_response.body, "select an active API key"
    assert_nil revoked_at(other_key_id)
  end

  def test_revoke_refuses_revoked_api_key
    setup_app
    id, = create_key
    create_key
    DB[:account_api_keys].where(id: id).update(revoked_at: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, days: 1))
    before = revoked_at(id)
    login

    post "/revoke-api-key", "api_key_id" => id.to_s, "password" => PASSWORD

    assert_equal 422, last_response.status
    assert_equal before, revoked_at(id)
  end

  def test_revoke_refuses_invalid_id
    setup_app
    create_key
    login

    ["abc", "1.5", "99999999999999999999"].each do |value|
      post "/revoke-api-key", "api_key_id" => value, "password" => PASSWORD
      assert_equal 422, last_response.status
    end
  end

  def test_api_key_cannot_revoke_api_key
    setup_app
    id, api_key = create_key

    post "/revoke-api-key", {"api_key_id" => id.to_s}, {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}

    assert_equal 403, last_response.status
    assert_nil revoked_at(id)
  end

  def test_revoke_hooks
    calls = []
    setup_app do
      before_revoke_api_key { calls << :before }
      after_revoke_api_key { calls << :after }
    end
    id, = create_key
    login

    post "/revoke-api-key", "api_key_id" => id.to_s, "password" => PASSWORD

    assert_equal [:before, :after], calls
  end

  def test_json_revoke
    setup_app(json: true)
    id, = create_key
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/revoke-api-key", "api_key_id" => id, "password" => PASSWORD)

    assert_equal 200, last_response.status
    assert_equal "The API key is revoked", body["success"]
    refute_nil revoked_at(id)
  end

  def test_json_revoke_error
    setup_app(json: true)
    create_key
    json_request("/login", login: LOGIN, password: PASSWORD)

    body = json_request("/revoke-api-key", "api_key_id" => 0, "password" => PASSWORD)

    assert_equal 422, last_response.status
    assert_equal "Unable to revoke the API key", body["error"]
    assert_equal ["api_key_id", "select an active API key"], body["field-error"]
  end

  def test_created_page_links_to_api_keys
    setup_app
    login

    post "/create-api-key", "api_key_name" => "CI", "password" => PASSWORD

    assert_includes last_response.body, 'href="/api-keys"'
  end
end
