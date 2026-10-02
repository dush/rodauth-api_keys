# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeys < RodauthTestCase
  def test_that_it_has_a_version_number
    refute_nil ::Rodauth::ApiKeys::VERSION
  end

  def test_harness_logs_in_with_password
    rodauth_app
    id = create_account

    get "/require-authentication"
    assert_equal 302, last_response.status

    login
    get "/require-authentication"
    assert_equal 200, last_response.status
    assert_equal id.to_s, last_response.body
  end

  def test_harness_sends_json_requests
    rodauth_app(json: true)
    create_account

    body = json_request("/login", login: LOGIN, password: PASSWORD)
    assert_equal 200, last_response.status
    assert_equal "You have been logged in", body["success"]
  end

  def test_harness_rolls_back_each_test
    assert_equal 0, DB[:accounts].count
  end
end
