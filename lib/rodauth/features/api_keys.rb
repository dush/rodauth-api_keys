# frozen_string_literal: true

module Rodauth
  Feature.define(:api_keys, :ApiKeys) do
    depends :require_hmac_secret

    # Format of an API key: "<api_key_prefix>_<secret>".
    auth_value_method :api_key_prefix, "rak"
    auth_value_method :api_key_secret_length, 43
    auth_value_method :api_key_hint_length, 4
    auth_value_method :api_key_realm, "api"

    # Database table and columns.
    auth_value_method :api_keys_table, :account_api_keys
    auth_value_method :api_keys_id_column, :id
    auth_value_method :api_keys_account_id_column, :account_id
    auth_value_method :api_keys_name_column, :name
    auth_value_method :api_keys_digest_column, :digest
    auth_value_method :api_keys_hint_column, :hint
    auth_value_method :api_keys_scopes_column, :scopes
    auth_value_method :api_keys_created_at_column, :created_at
    auth_value_method :api_keys_last_use_column, :last_use
    auth_value_method :api_keys_expires_at_column, :expires_at
    auth_value_method :api_keys_revoked_at_column, :revoked_at

    # Limits and policies.
    auth_value_method :api_keys_limit, 10
    auth_value_method :api_key_scopes, [].freeze
    auth_value_method :api_key_max_lifetime, nil
    auth_value_method :api_key_last_use_update_interval, 60
    auth_value_method :revoke_api_keys_on_password_change?, false

    # Request parameters.
    auth_value_method :api_key_name_param, "api_key_name"
    auth_value_method :api_key_expires_at_param, "api_key_expires_at"
    auth_value_method :api_key_scopes_param, "api_key_scopes"
    auth_value_method :api_key_id_param, "api_key_id"

    # Responses for API key authentication.
    session_key :api_key_id_session_key, :api_key_id
    translatable_method :invalid_api_key_message, "invalid API key"
    translatable_method :api_key_required_message, "API key required"
    translatable_method :insufficient_api_key_scope_message, "API key does not have the necessary scope"
    auth_value_method :insufficient_api_key_scope_error_status, 403

    auth_value_methods :api_key_authorization_regexp

    auth_methods(
      :api_key_authenticated?,
      :api_key_digest,
      :api_key_digests,
      :api_key_from_request,
      :api_key_hint,
      :api_key_insert_hash,
      :api_key_scope?,
      :create_api_key,
      :generate_api_key,
      :require_api_key_authentication,
      :require_api_key_scope,
      :update_api_key_last_use
    )

    uses_instance_variables(:@created_api_key_id, :@session, :@api_key_row)

    # The ID of the row that the last call to create_api_key added.
    attr_reader :created_api_key_id

    # The first capture group must contain the API key.
    def api_key_authorization_regexp
      /\ABearer\s+(#{Regexp.escape(api_key_prefix)}_[A-Za-z0-9]+)\s*\z/
    end

    def post_configure
      super

      unless api_key_prefix.is_a?(String) && api_key_prefix.match?(/\A[A-Za-z0-9]+(?:_[A-Za-z0-9]+)*\z/)
        raise ConfigurationError, "api_key_prefix must contain only letters, digits, and single underscores between them: #{api_key_prefix.inspect}"
      end

      # This feature overrides methods of these features. Thus it must come before them in the method lookup.
      ancestors = self.class.ancestors
      [:two_factor_base].each do |feature_name|
        next unless (feature = FEATURES[feature_name]) && ancestors.include?(feature)
        if ancestors.index(feature) < ancestors.index(FEATURES[:api_keys])
          raise ConfigurationError, "enable :api_keys after :#{feature_name} and the features that use it"
        end
      end

      api_key_scopes.each do |scope|
        unless scope.is_a?(String) && scope.match?(/\A[!#-\[\]-~]+\z/)
          raise ConfigurationError, "api_key_scopes must contain only strings of printable ASCII characters without spaces, quotes, or backslashes: #{scope.inspect}"
        end
      end
    end

    # When the request contains an API key, return a session hash for this request only.
    # Rodauth does not write this hash to the session cookie.
    # When the API key is not valid, send a 401 response. Do not use the cookie session.
    def session
      return @session if @session
      return super unless (api_key = api_key_from_request)

      @session = api_key_session(api_key)
    end

    # Return the API key from the Authorization header, or nil.
    def api_key_from_request
      (value = request.env["HTTP_AUTHORIZATION"]) && value[api_key_authorization_regexp, 1]
    end

    # Return true if an API key authenticated the request.
    def api_key_authenticated?
      session
      !@api_key_row.nil?
    end

    # Return the ID of the API key that authenticated the request, or nil.
    def current_api_key_id
      @api_key_row[api_keys_id_column] if api_key_authenticated?
    end

    # Return the scopes of the API key that authenticated the request, or nil.
    def current_api_key_scopes
      @api_key_row[api_keys_scopes_column].to_s.split(" ") if api_key_authenticated?
    end

    # Send a 401 response if no valid API key authenticated the request.
    def require_api_key_authentication
      return if api_key_authenticated?

      set_response_error_reason_status(:api_key_required, login_required_error_status)
      set_response_header("www-authenticate", "Bearer realm=\"#{api_key_realm}\"")
      return_api_key_error_response(api_key_required_message)
    end

    # Return true if the request has permission for the scope.
    # A request that the cookie session authenticated has all scopes.
    def api_key_scope?(scope)
      if api_key_authenticated?
        current_api_key_scopes.include?(scope.to_s)
      else
        !!authenticated?
      end
    end

    # Require authentication. Then send a 403 response if the API key does not have all the scopes.
    def require_api_key_scope(*scopes)
      require_authentication
      return if scopes.all? { |scope| api_key_scope?(scope) }

      set_response_error_reason_status(:insufficient_api_key_scope, insufficient_api_key_scope_error_status)
      set_response_header("www-authenticate", "Bearer realm=\"#{api_key_realm}\", error=\"insufficient_scope\", scope=\"#{scopes.join(" ")}\"")
      return_api_key_error_response(insufficient_api_key_scope_message)
    end

    # The account used all its authentication factors when it created the API key.
    def two_factor_authenticated?
      api_key_authenticated? || super
    end

    # Return all digests that can match the API key. With hmac_old_secret, there are two digests.
    def api_key_digests(api_key)
      compute_hmacs(api_key)
    end

    # Record the time of use. Skip the update if the last update is more recent than api_key_last_use_update_interval.
    def update_api_key_last_use
      ds = api_keys_table_ds.where(api_keys_id_column => @api_key_row[api_keys_id_column])
      if (interval = api_key_last_use_update_interval)
        last_use = Sequel[api_keys_last_use_column]
        ds = ds.where(Sequel.|({last_use => nil}, last_use < Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: interval)))
      end
      ds.update(api_keys_last_use_column => Sequel::CURRENT_TIMESTAMP)
    end

    # Return a new API key: the prefix, an underscore, and a random secret.
    # The secret contains only letters and digits.
    def generate_api_key
      "#{api_key_prefix}_#{SecureRandom.alphanumeric(api_key_secret_length)}"
    end

    # Return the value that the database keeps in place of the API key.
    def api_key_digest(api_key)
      compute_hmac(api_key)
    end

    # Return the start of the API key: the prefix, the underscore, and the first characters of the secret.
    # The list of API keys shows this value.
    def api_key_hint(api_key)
      api_key[0, api_key_prefix.length + 1 + api_key_hint_length]
    end

    # Add an API key for the account. Return the API key.
    # The database keeps only the key digest and the key hint.
    # expires_in is the lifetime in seconds. When it is nil, the API key does not expire.
    def create_api_key(name, scopes: [], expires_in: nil)
      @created_api_key_id = nil
      3.times do |attempt|
        api_key = generate_api_key
        hash = api_key_insert_hash(api_key, name, scopes, expires_in)
        error = raised_uniqueness_violation { @created_api_key_id = api_keys_table_ds.insert(hash) }
        return api_key unless error

        # Two equal digests are almost impossible. Try again with a new API key.
        raise error if attempt == 2
      end
    end

    private

    def api_key_insert_hash(api_key, name, scopes, expires_in)
      hash = {
        api_keys_account_id_column => account_id,
        api_keys_name_column => name,
        api_keys_digest_column => api_key_digest(api_key),
        api_keys_hint_column => api_key_hint(api_key),
        api_keys_scopes_column => (scopes.join(" ") unless scopes.empty?)
      }
      if expires_in
        # The database calculates the expiration time with its own clock, as Rodauth does for deadlines.
        hash[api_keys_expires_at_column] = Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: expires_in)
      end
      hash
    end

    def use_date_arithmetic?
      true
    end

    # Find the active API key and its account. Return the session hash for the request.
    def api_key_session(api_key)
      digests = api_key_digests(api_key)
      row = api_keys_table_ds.where(api_keys_digest_column => digests).where(active_api_key_condition).first
      invalid_api_key_response unless row

      # Use the account checks of a cookie session: the account must exist and be open.
      @session = {
        session_key => row[api_keys_account_id_column],
        authenticated_by_session_key => ["api_key"],
        api_key_id_session_key => row[api_keys_id_column]
      }
      invalid_api_key_response unless account_from_session

      @api_key_row = row
      if hmac_secret_rotation? && row[api_keys_digest_column] != digests.first
        api_keys_table_ds.where(api_keys_id_column => row[api_keys_id_column]).update(api_keys_digest_column => digests.first)
      end
      update_api_key_last_use
      @session
    end

    def invalid_api_key_response
      @session = {}
      @account = nil
      set_response_error_reason_status(:invalid_api_key, invalid_key_error_status)
      set_response_header("www-authenticate", "Bearer realm=\"#{api_key_realm}\", error=\"invalid_token\"")
      return_api_key_error_response(invalid_api_key_message)
    end

    # Send the error message as JSON when the application enables the json feature and the request uses JSON.
    # Otherwise, send it as plain text.
    def return_api_key_error_response(message)
      if respond_to?(:use_json?) && use_json?
        json_response[json_response_error_key] = message
        return_json_response
      else
        response.headers[convert_response_header_key("content-type")] = "text/plain"
        return_response(message)
      end
    end

    # Do not clear the cookie session for a request that an API key authenticated.
    def use_scope_clear_session?
      super && !api_key_authenticated?
    end

    # All API keys in the table, for all accounts.
    def api_keys_table_ds
      db[api_keys_table]
    end

    # All API keys of the account.
    def api_keys_ds(id = account_id)
      api_keys_table_ds.where(api_keys_account_id_column => id)
    end

    # The API keys of the account that are not revoked and not expired.
    def active_api_keys_ds(id = account_id)
      api_keys_ds(id).where(active_api_key_condition)
    end

    # An API key is active when it is not revoked and not expired.
    def active_api_key_condition
      expires_at = Sequel[api_keys_expires_at_column]
      Sequel.&(
        {api_keys_revoked_at_column => nil},
        Sequel.|({expires_at => nil}, expires_at > Sequel::CURRENT_TIMESTAMP)
      )
    end
  end
end
