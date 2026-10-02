# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysConfiguration < RodauthTestCase
  def test_default_values
    r = rodauth_object

    assert_equal "rak", r.api_key_prefix
    assert_equal 43, r.api_key_secret_length
    assert_equal 4, r.api_key_hint_length
    assert_equal "api", r.api_key_realm
    assert_equal :account_api_keys, r.api_keys_table
    assert_equal 10, r.api_keys_limit
    assert_equal [], r.api_key_scopes
    assert_nil r.api_key_max_lifetime
    assert_equal 60, r.api_key_last_use_update_interval
    refute r.revoke_api_keys_on_password_change?
    assert_equal "api_key_name", r.api_key_name_param
    assert_equal "api_key_expires_at", r.api_key_expires_at_param
    assert_equal "api_key_scopes", r.api_key_scopes_param
    assert_equal "api_key_id", r.api_key_id_param
  end

  def test_default_column_names
    r = rodauth_object

    assert_equal(
      [:id, :account_id, :name, :digest, :hint, :scopes, :created_at, :last_use, :expires_at, :revoked_at],
      [
        r.api_keys_id_column, r.api_keys_account_id_column, r.api_keys_name_column,
        r.api_keys_digest_column, r.api_keys_hint_column, r.api_keys_scopes_column,
        r.api_keys_created_at_column, r.api_keys_last_use_column,
        r.api_keys_expires_at_column, r.api_keys_revoked_at_column
      ]
    )
  end

  def test_configuration_changes_values
    r = rodauth_object do
      api_key_prefix "myapp_live"
      api_keys_limit 3
      api_key_scopes %w[read write]
      api_key_max_lifetime 86400 * 90
      revoke_api_keys_on_password_change? true
    end

    assert_equal "myapp_live", r.api_key_prefix
    assert_equal 3, r.api_keys_limit
    assert_equal %w[read write], r.api_key_scopes
    assert_equal 86400 * 90, r.api_key_max_lifetime
    assert r.revoke_api_keys_on_password_change?
  end

  def test_authorization_regexp_accepts_bearer_with_prefix
    regexp = rodauth_object.api_key_authorization_regexp

    assert_equal "rak_Abc123", regexp.match("Bearer rak_Abc123")[1]
    assert_equal "rak_Abc123", regexp.match("Bearer   rak_Abc123  ")[1]
  end

  def test_authorization_regexp_refuses_other_values
    regexp = rodauth_object.api_key_authorization_regexp

    [
      "rak_Abc123",
      "Basic rak_Abc123",
      "Token rak_Abc123",
      "Bearer other_Abc123",
      "Bearer rak_",
      "Bearer rak_Abc-123",
      "Bearer rak_Abc123 extra",
      "Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc"
    ].each do |value|
      assert_nil regexp.match(value), "regexp must refuse #{value.inspect}"
    end
  end

  def test_authorization_regexp_uses_configured_prefix
    regexp = rodauth_object { api_key_prefix "myapp_live" }.api_key_authorization_regexp

    assert_equal "myapp_live_Abc123", regexp.match("Bearer myapp_live_Abc123")[1]
    assert_nil regexp.match("Bearer rak_Abc123")
  end

  def test_authorization_regexp_can_change
    r = rodauth_object do
      api_key_authorization_regexp(/\A(?:Bearer|Token)\s+(rak_[A-Za-z0-9]+)\z/)
    end

    assert_equal "rak_Abc123", r.api_key_authorization_regexp.match("Token rak_Abc123")[1]
  end

  def test_invalid_prefix_raises_configuration_error
    ["", "my-app", "_rak", "rak_", "my__app", "my app", :rak].each do |prefix|
      assert_raises(Rodauth::ConfigurationError, "prefix #{prefix.inspect} must raise") do
        rodauth_object { api_key_prefix prefix }
      end
    end
  end

  def test_invalid_scope_raises_configuration_error
    ["", "read write", "a\"b", "a\\b", "čtení", :read].each do |scope|
      assert_raises(Rodauth::ConfigurationError, "scope #{scope.inspect} must raise") do
        rodauth_object { api_key_scopes [scope] }
      end
    end
  end

  def test_valid_scopes_do_not_raise
    r = rodauth_object { api_key_scopes %w[read write:repo admin.users] }

    assert_equal %w[read write:repo admin.users], r.api_key_scopes
  end

  def test_api_keys_ds_contains_only_the_keys_of_the_account
    r = rodauth_object
    id = create_account
    other_id = create_account(login: "bar@example.com")
    key_id = insert_api_key(id)
    insert_api_key(other_id)

    assert_equal [key_id], r.send(:api_keys_ds, id).select_map(:id)
  end

  def test_active_api_keys_ds_skips_revoked_and_expired_keys
    r = rodauth_object
    id = create_account
    active_id = insert_api_key(id)
    future_id = insert_api_key(id, expires_at: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, days: 1))
    insert_api_key(id, expires_at: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, days: 1))
    insert_api_key(id, revoked_at: Sequel::CURRENT_TIMESTAMP)
    insert_api_key(id, revoked_at: Sequel::CURRENT_TIMESTAMP, expires_at: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, days: 1))

    assert_equal [active_id, future_id].sort, r.send(:active_api_keys_ds, id).select_map(:id).sort
    assert_equal 5, r.send(:api_keys_ds, id).count
  end

  def test_datasets_use_configured_table_and_columns
    DB.create_table(:other_api_keys) do
      primary_key :key_id
      Integer :owner_id
      DateTime :valid_until
      DateTime :cancelled_at
    end
    r = rodauth_object do
      api_keys_table :other_api_keys
      api_keys_account_id_column :owner_id
      api_keys_expires_at_column :valid_until
      api_keys_revoked_at_column :cancelled_at
    end
    DB[:other_api_keys].insert(owner_id: 1)
    DB[:other_api_keys].insert(owner_id: 1, cancelled_at: Sequel::CURRENT_TIMESTAMP)
    DB[:other_api_keys].insert(owner_id: 2)

    assert_equal 2, r.send(:api_keys_ds, 1).count
    assert_equal 1, r.send(:active_api_keys_ds, 1).count
  end
end
