# frozen_string_literal: true

require "test_helper"

# An API key must not use the Rodauth routes. It must not manage the account.
class Rodauth::TestApiKeysRodauthRoutes < RodauthTestCase
  NEW_LOGIN = "bar@example.com"

  def create_key(account_id)
    r = app.rodauth.allocate
    r.account_from_id(account_id)
    r.create_api_key("key")
  end

  def bearer(api_key)
    {"HTTP_AUTHORIZATION" => "Bearer #{api_key}"}
  end

  # Make an open account without a password. Rodauth does not ask for a password to change it.
  def create_account_without_password
    DB[:accounts].insert(email: LOGIN, status_id: 2)
  end

  def test_api_key_cannot_change_login_of_account_without_password
    rodauth_app(json: true) do
      enable :change_login, :api_keys
      require_login_confirmation? false
    end
    account_id = create_account_without_password
    api_key = create_key(account_id)

    body = json_request("/change-login", {"login" => NEW_LOGIN}, bearer(api_key))

    assert_equal 403, last_response.status
    assert_equal "an API key cannot use this route", body["error"]
    assert_equal LOGIN, DB[:accounts].where(id: account_id).get(:email)
  end

  def test_api_key_cannot_use_html_route
    rodauth_app do
      enable :change_login, :api_keys
      require_login_confirmation? false
    end
    account_id = create_account_without_password
    api_key = create_key(account_id)

    post "/change-login", {"login" => NEW_LOGIN}, bearer(api_key)

    assert_equal 403, last_response.status
    assert_equal "an API key cannot use this route", last_response.body
    assert_equal LOGIN, DB[:accounts].where(id: account_id).get(:email)
  end

  # A remember cookie authenticates the account without the API key, also after the revocation of the API key.
  def test_api_key_cannot_set_remember_cookie
    rodauth_app(json: true) { enable :remember, :api_keys }
    account_id = create_account
    api_key = create_key(account_id)

    body = json_request("/remember", {"remember" => "remember"}, bearer(api_key))

    assert_equal 403, last_response.status
    assert_equal "an API key cannot use this route", body["error"]
    assert_nil last_response["set-cookie"]
    assert_equal 0, DB[:account_remember_keys].count
  end

  def test_before_rodauth_block_does_not_remove_check
    hook_calls = 0
    rodauth_app(json: true) do
      enable :change_login, :api_keys
      require_login_confirmation? false
      before_rodauth { hook_calls += 1 }
    end
    account_id = create_account_without_password
    api_key = create_key(account_id)

    json_request("/change-login", {"login" => NEW_LOGIN}, bearer(api_key))

    assert_equal 403, last_response.status
    assert_equal 0, hook_calls
    assert_equal LOGIN, DB[:accounts].where(id: account_id).get(:email)
  end

  def test_before_rodauth_block_runs_for_cookie_session
    hook_calls = 0
    rodauth_app do
      enable :api_keys
      before_rodauth { hook_calls += 1 }
    end
    create_account

    login

    assert_equal 302, last_response.status
    assert_equal 1, hook_calls
  end
end
