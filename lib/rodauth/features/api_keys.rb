# frozen_string_literal: true

require "date"
require "time"

module Rodauth
  Feature.define(:api_keys, :ApiKeys) do
    depends :require_hmac_secret

    # Page to create an API key.
    notice_flash "Your API key is ready. Copy it now. You cannot see it again.", "create_api_key"
    error_flash "Unable to create the API key", "create_api_key"
    loaded_templates %w[api-keys create-api-key api-key-created revoke-api-key password-field]
    view "create-api-key", "Create API Key", "create_api_key"
    view "api-key-created", "API Key Created", "api_key_created"
    additional_form_tags "create_api_key"
    button "Create API Key", "create_api_key"
    before "create_api_key"
    after "create_api_key"

    translatable_method :api_key_label, "API key"
    translatable_method :api_key_name_label, "Name"
    translatable_method :api_key_expires_at_label, "Expiration date"
    translatable_method :api_key_scopes_label, "Scopes"
    translatable_method :invalid_api_key_name_message, "invalid name"
    translatable_method :invalid_api_key_expires_at_message, "invalid expiration date"
    translatable_method :api_key_expires_at_required_message, "expiration date is necessary"
    translatable_method :api_key_expires_at_past_message, "expiration date must be in the future"
    translatable_method :api_key_expires_at_too_late_message, "expiration date is too late"
    translatable_method :invalid_api_key_scopes_message, "invalid scope"
    translatable_method :api_key_scopes_required_message, "select one or more scopes"
    translatable_method :api_keys_limit_message, "maximum number of active API keys"
    translatable_method :api_key_management_not_permitted_message, "an API key cannot manage API keys"
    auth_value_method :api_key_management_not_permitted_error_status, 403

    # Page with the list of API keys.
    view "api-keys", "API Keys", "api_keys"
    translatable_method :api_key_created_at_label, "Created"
    translatable_method :api_key_last_use_label, "Last use"
    translatable_method :api_key_status_label, "Status"
    translatable_method :api_key_active_label, "Active"
    translatable_method :api_key_expired_label, "Expired"
    translatable_method :api_key_revoked_label, "Revoked"
    translatable_method :api_key_never_label, "Never"
    translatable_method :api_keys_empty_message, "There are no API keys."
    translatable_method :create_api_key_link_text, "Create API Key"
    translatable_method :revoke_api_key_link_text, "Revoke API Key"

    # Page to revoke an API key.
    notice_flash "The API key is revoked", "revoke_api_key"
    error_flash "Unable to revoke the API key", "revoke_api_key"
    view "revoke-api-key", "Revoke API Key", "revoke_api_key"
    additional_form_tags "revoke_api_key"
    button "Revoke API Key", "revoke_api_key"
    before "revoke_api_key"
    after "revoke_api_key"
    redirect(:revoke_api_key) { api_keys_path }
    response "revoke_api_key"
    translatable_method :invalid_api_key_id_message, "select an active API key"
    translatable_method :no_active_api_keys_message, "There are no active API keys."

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
    auth_value_method :api_key_name_max_length, 100
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
      :account_api_keys,
      :revoke_all_api_keys,
      :revoke_api_key,
      :api_key_created_response,
      :parse_api_key_expires_at,
      :valid_api_key_name?,
      :valid_api_key_scopes?,
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

    uses_instance_variables(:@created_api_key_id, :@created_api_key, :@session, :@api_key_row)

    # The ID of the row that the last call to create_api_key added.
    attr_reader :created_api_key_id

    # The API key that the create-api-key route added in this request. The created page shows it.
    attr_reader :created_api_key

    route(:api_keys) do |r|
      require_account
      require_api_key_management_session
      before_api_keys_route

      if respond_to?(:use_json?) && use_json?
        json_response["api_keys"] = account_api_keys.map { |api_key| api_key_json(api_key) }
      end

      r.get do
        api_keys_view
      end

      r.post do
        api_keys_view
      end
    end

    route(:revoke_api_key) do |r|
      require_account
      require_api_key_management_session
      before_revoke_api_key_route

      r.get do
        revoke_api_key_view
      end

      r.post do
        catch_error do
          unless (id = param_or_nil(api_key_id_param))
            throw_error_reason(:invalid_api_key_id, invalid_field_error_status, api_key_id_param, invalid_api_key_id_message)
          end

          if modifications_require_password? && !password_match?(param(password_param))
            throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
          end

          transaction do
            before_revoke_api_key
            unless revoke_api_key(id)
              throw_error_reason(:invalid_api_key_id, invalid_field_error_status, api_key_id_param, invalid_api_key_id_message)
            end
            after_revoke_api_key
          end

          revoke_api_key_response
        end

        set_error_flash revoke_api_key_error_flash
        revoke_api_key_view
      end
    end

    route(:create_api_key) do |r|
      require_account
      require_api_key_management_session
      before_create_api_key_route

      r.get do
        create_api_key_view
      end

      r.post do
        catch_error do
          if modifications_require_password? && !password_match?(param(password_param))
            throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
          end

          name = api_key_name_param_value
          scopes = api_key_scopes_param_value
          expires_in = api_key_expires_in_param_value

          transaction do
            before_create_api_key
            if api_keys_limit && active_api_keys_ds.count >= api_keys_limit
              throw_error_reason(:api_keys_limit, invalid_field_error_status, api_key_name_param, api_keys_limit_message)
            end
            @created_api_key = create_api_key(name, scopes: scopes, expires_in: expires_in)
            after_create_api_key
          end

          api_key_created_response
        end

        set_error_flash create_api_key_error_flash
        create_api_key_view
      end
    end

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
      [:two_factor_base, :jwt].each do |feature_name|
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

    # Return true if the name is not empty and not too long.
    def valid_api_key_name?(name)
      !name.empty? && name.length <= api_key_name_max_length
    end

    # Return true if api_key_scopes contains each scope.
    def valid_api_key_scopes?(scopes)
      scopes.all? { |scope| scope.is_a?(String) && api_key_scopes.include?(scope) }
    end

    # Return the expiration time for the value of the form field, or nil if the value is not valid.
    # A date without a time ("2026-12-31") is the last second of that day in the time zone of the application.
    # A full ISO 8601 time ("2026-12-31T12:00:00Z") is also valid.
    def parse_api_key_expires_at(value)
      if value.match?(/\A\d{4}-\d{2}-\d{2}\z/)
        date = Date.iso8601(value)
        Time.new(date.year, date.month, date.day, 23, 59, 59)
      else
        Time.iso8601(value)
      end
    rescue ArgumentError
      nil
    end

    # Return the API keys of the account, the newest first. Each item is a hash with these keys:
    # :id, :name, :hint, :scopes (array), :created_at, :last_use, :expires_at, :revoked_at, and :status.
    # The status is :active, :expired, or :revoked. The database calculates it with its own clock.
    def account_api_keys
      status = Sequel.case(
        [
          [{api_keys_revoked_at_column => nil}, Sequel.case([[active_api_key_condition, "active"]], "expired")]
        ],
        "revoked"
      )
      api_keys_ds.select_append(status.as(:api_key_status)).reverse(api_keys_id_column).map do |row|
        {
          id: row[api_keys_id_column],
          name: row[api_keys_name_column],
          hint: row[api_keys_hint_column],
          scopes: row[api_keys_scopes_column].to_s.split(" "),
          created_at: convert_timestamp(row[api_keys_created_at_column]),
          last_use: convert_timestamp(row[api_keys_last_use_column]),
          expires_at: convert_timestamp(row[api_keys_expires_at_column]),
          revoked_at: convert_timestamp(row[api_keys_revoked_at_column]),
          status: row[:api_key_status].to_sym
        }
      end
    end

    # Revoke the active API key of the account with this ID. Return true if the API key was active.
    def revoke_api_key(id)
      return false unless (id = convert_token_id(id))

      active_api_keys_ds.where(api_keys_id_column => id).update(api_keys_revoked_at_column => Sequel::CURRENT_TIMESTAMP) == 1
    end

    # Revoke all active API keys of the account. Return the number of revoked API keys.
    def revoke_all_api_keys
      active_api_keys_ds.update(api_keys_revoked_at_column => Sequel::CURRENT_TIMESTAMP)
    end

    # Rodauth calls this method after a password change, a password reset, and other changes to the account.
    def clear_tokens(reason)
      super
      if revoke_api_keys_on_password_change? && [:change_password, :reset_password].include?(reason)
        revoke_all_api_keys
      end
    end

    # The jwt feature reads each Authorization header that does not start with Basic or Digest.
    # Do not let it read an API key.
    def jwt_token
      return if api_key_from_request

      super
    end

    # Show the new API key one time. Tell the browser and proxies not to keep a copy of the page.
    def api_key_created_response
      set_response_header("cache-control", "no-store")
      set_notice_now_flash create_api_key_notice_flash

      if respond_to?(:use_json?) && use_json?
        row = api_keys_table_ds.where(api_keys_id_column => created_api_key_id).first
        expires_at = row[api_keys_expires_at_column]
        json_response.merge!(
          "api_key" => created_api_key,
          "api_key_id" => created_api_key_id,
          "name" => row[api_keys_name_column],
          "hint" => row[api_keys_hint_column],
          "scopes" => row[api_keys_scopes_column].to_s.split(" "),
          "expires_at" => (convert_timestamp(expires_at).iso8601 if expires_at)
        )
        return_json_response
      end

      return_response(api_key_created_view)
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

    # A closed account must not use its API keys.
    # If close_account calls delete_account, remove the API key rows first, because of the foreign key.
    def after_close_account
      super if defined?(super)
      if delete_account_on_close?
        api_keys_ds.delete
      else
        revoke_all_api_keys
      end
    end

    # Do not send a JWT in a response to a request that an API key authenticated.
    # Such a JWT would authenticate the account without the API key, also after the revocation of the API key.
    def set_jwt
      super unless @api_key_row
    end

    def api_key_json(api_key)
      api_key.transform_keys(&:to_s).merge(
        "status" => api_key[:status].to_s,
        "created_at" => api_key[:created_at]&.iso8601,
        "last_use" => api_key[:last_use]&.iso8601,
        "expires_at" => api_key[:expires_at]&.iso8601,
        "revoked_at" => api_key[:revoked_at]&.iso8601
      )
    end

    def template_path(page)
      path = File.expand_path("../../../templates/#{page}.str", __dir__)
      File.file?(path) ? path : super
    end

    # An API key must not create or revoke API keys. Send a 403 response for a request that an API key authenticated.
    def require_api_key_management_session
      return unless api_key_authenticated?

      set_response_error_reason_status(:api_key_management_not_permitted, api_key_management_not_permitted_error_status)
      return_api_key_error_response(api_key_management_not_permitted_message)
    end

    def api_key_name_param_value
      name = param(api_key_name_param).strip
      unless valid_api_key_name?(name)
        throw_error_reason(:invalid_api_key_name, invalid_field_error_status, api_key_name_param, invalid_api_key_name_message)
      end
      name
    end

    # The parameter can be an array (HTML check boxes or JSON) or a string with scopes separated by spaces.
    def api_key_scopes_param_value
      scopes = case (value = raw_param(api_key_scopes_param))
      when nil then []
      when Array then value.uniq
      when String then value.split.uniq
      end

      unless scopes && valid_api_key_scopes?(scopes)
        throw_error_reason(:invalid_api_key_scopes, invalid_field_error_status, api_key_scopes_param, invalid_api_key_scopes_message)
      end
      if scopes.empty? && !api_key_scopes.empty?
        throw_error_reason(:api_key_scopes_required, invalid_field_error_status, api_key_scopes_param, api_key_scopes_required_message)
      end
      scopes
    end

    # Return the lifetime in seconds, or nil for an API key that does not expire.
    def api_key_expires_in_param_value
      value = param(api_key_expires_at_param).strip
      if value.empty?
        if api_key_max_lifetime
          throw_error_reason(:api_key_expires_at_required, invalid_field_error_status, api_key_expires_at_param, api_key_expires_at_required_message)
        end
        return
      end

      unless (expires_at = parse_api_key_expires_at(value))
        throw_error_reason(:invalid_api_key_expires_at, invalid_field_error_status, api_key_expires_at_param, invalid_api_key_expires_at_message)
      end

      expires_in = (expires_at - Time.now).ceil
      if expires_in <= 0
        throw_error_reason(:api_key_expires_at_past, invalid_field_error_status, api_key_expires_at_param, api_key_expires_at_past_message)
      end
      if api_key_max_lifetime && expires_in > api_key_max_lifetime
        throw_error_reason(:api_key_expires_at_too_late, invalid_field_error_status, api_key_expires_at_param, api_key_expires_at_too_late_message)
      end
      expires_in
    end

    # Find the active API key and its account. Return the session hash for the request.
    def api_key_session(api_key)
      digests = api_key_digests(api_key)
      row = api_keys_table_ds.where(api_keys_digest_column => digests).where(active_api_key_condition).first
      invalid_api_key_response unless row

      # Use the account checks of a cookie session: the account must exist and be open.
      # Do not keep the account. A Rodauth route loads it again and shows a warning when it loads it two times.
      @session = {
        session_key => row[api_keys_account_id_column],
        authenticated_by_session_key => ["api_key"],
        api_key_id_session_key => row[api_keys_id_column]
      }
      invalid_api_key_response unless _account_from_session

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
