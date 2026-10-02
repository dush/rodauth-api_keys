# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "rodauth/api_keys"

require "bcrypt"
require "json"
require "rack/test"
require "roda"
require "securerandom"
require "sequel"

require "minitest/autorun"

DB = Sequel.sqlite
DB.extension :date_arithmetic
Sequel.extension :migration
Sequel::Migrator.run(DB, File.expand_path("migrate", __dir__))
DB.freeze

# Base class for tests that send requests to a Roda app with Rodauth.
class RodauthTestCase < Minitest::Test
  include Rack::Test::Methods

  LOGIN = "foo@example.com"
  PASSWORD = "0123456789"
  LAYOUT = "<html><body><p id=\"error\">\#{flash[:error]}</p><p id=\"notice\">\#{flash[:notice]}</p>\#{yield}</body></html>"

  attr_reader :app

  # Run each test in a transaction. The transaction rolls back after the test.
  def run
    DB.transaction(rollback: :always, auto_savepoint: true) { super }
  end

  # Make a Roda app. The block configures Rodauth.
  # Without a route block, the app supplies these routes:
  # - "/" returns the account ID, or an empty string.
  # - "/require-authentication" returns the account ID after require_authentication.
  def rodauth_app(json: false, csrf: false, route: nil, &config)
    app = Class.new(Roda)
    app.plugin :sessions, secret: SecureRandom.random_bytes(64), key: "rack.session"
    app.plugin :flash
    app.plugin :render, layout_opts: {inline: LAYOUT}
    app.plugin :json_parser, content_type_regexp: /\Aapplication\/json\b/i if json

    rodauth_opts = {}
    rodauth_opts[:json] = true if json
    rodauth_opts[:csrf] = false unless csrf
    app.plugin(:rodauth, rodauth_opts) do
      enable :login, :logout
      enable :json if json
      hmac_secret "test-hmac-secret"
      already_logged_in { raise "already logged in" }
      instance_exec(&config) if config
    end

    route ||= proc do |r|
      r.rodauth
      r.root { rodauth.session_value.to_s }
      r.get "require-authentication" do
        rodauth.require_authentication
        rodauth.session_value.to_s
      end
    end
    app.route(&route)
    app.freeze
    @app = app
  end

  # Add an open account with a password. Return the account ID.
  def create_account(login: LOGIN, password: PASSWORD)
    id = DB[:accounts].insert(email: login, status_id: 2)
    hash = BCrypt::Password.create(password, cost: BCrypt::Engine::MIN_COST)
    DB[:account_password_hashes].insert(id: id, password_hash: hash)
    id
  end

  def login(login: LOGIN, password: PASSWORD)
    post "/login", "login" => login, "password" => password
  end

  # Send a JSON request. Return the parsed response body.
  def json_request(path, params = {}, headers = {})
    post path, params.to_json, {"CONTENT_TYPE" => "application/json"}.merge(headers)
    JSON.parse(last_response.body)
  end
end
