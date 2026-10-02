# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysCreate < RodauthTestCase
  # Return a Rodauth object for a new account.
  def rodauth_for_account(&config)
    r = rodauth_object(&config)
    r.account_from_id(create_account)
    r
  end

  # Return the row in the API keys table for the last API key that r created.
  def created_row(r)
    DB[:account_api_keys].where(id: r.created_api_key_id).first
  end

  def test_generate_api_key_format
    api_key = rodauth_object.generate_api_key

    assert_match(/\Arak_[A-Za-z0-9]{43}\z/, api_key)
  end

  def test_generate_api_key_returns_different_values
    r = rodauth_object
    api_keys = Array.new(100) { r.generate_api_key }

    assert_equal 100, api_keys.uniq.length
  end

  def test_generate_api_key_uses_configured_prefix_and_length
    api_key = rodauth_object {
      api_key_prefix "myapp_live"
      api_key_secret_length 50
    }.generate_api_key

    assert_match(/\Amyapp_live_[A-Za-z0-9]{50}\z/, api_key)
  end

  def test_generated_api_key_matches_authorization_regexp
    r = rodauth_object { api_key_prefix "myapp_live" }
    api_key = r.generate_api_key

    assert_equal api_key, r.api_key_authorization_regexp.match("Bearer #{api_key}")[1]
  end

  def test_api_key_digest_is_hmac_of_api_key
    r = rodauth_object
    api_key = r.generate_api_key

    assert_equal r.compute_hmac(api_key), r.api_key_digest(api_key)
    assert_equal r.api_key_digest(api_key), r.api_key_digest(api_key.dup)
    refute_equal r.api_key_digest(api_key), r.api_key_digest(r.generate_api_key)
    refute_includes r.api_key_digest(api_key), api_key.delete_prefix("rak_")
  end

  def test_api_key_digest_uses_hmac_secret
    api_key = "rak_#{"A" * 43}"
    digest = rodauth_object.api_key_digest(api_key)

    refute_equal digest, rodauth_object { hmac_secret "other-secret" }.api_key_digest(api_key)
  end

  def test_api_key_hint
    assert_equal "rak_Abcd", rodauth_object.api_key_hint("rak_AbcdEfgh")
    assert_equal "myapp_live_Ab", rodauth_object {
      api_key_prefix "myapp_live"
      api_key_hint_length 2
    }.api_key_hint("myapp_live_AbcdEfgh")
  end

  def test_create_api_key_adds_row
    r = rodauth_for_account
    api_key = r.create_api_key("CI server")
    row = created_row(r)

    assert_equal r.account_id, row[:account_id]
    assert_equal "CI server", row[:name]
    assert_equal r.api_key_digest(api_key), row[:digest]
    assert_equal api_key[0, 8], row[:hint]
    assert_nil row[:scopes]
    assert_nil row[:expires_at]
    assert_nil row[:revoked_at]
    assert_nil row[:last_use]
    refute_nil row[:created_at]
    assert_equal [r.created_api_key_id], r.send(:active_api_keys_ds).select_map(:id)
  end

  def test_create_api_key_does_not_keep_the_api_key
    r = rodauth_for_account
    api_key = r.create_api_key("CI server")
    secret = api_key.delete_prefix("rak_")

    created_row(r).each_value do |value|
      refute_includes value.to_s, secret
    end
  end

  def test_create_api_key_keeps_scopes
    r = rodauth_for_account { api_key_scopes %w[read write admin] }
    r.create_api_key("CI server", scopes: %w[read write])

    assert_equal "read write", created_row(r)[:scopes]
  end

  def test_create_api_key_with_expiration
    r = rodauth_for_account
    r.create_api_key("CI server", expires_in: 3600)
    ds = DB[:account_api_keys].where(id: r.created_api_key_id)

    assert_equal 1, ds.where { expires_at > Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: 3590) }.count
    assert_equal 1, ds.where { expires_at < Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: 3610) }.count
    assert_equal 1, r.send(:active_api_keys_ds).count
  end

  def test_create_api_key_with_past_expiration_is_not_active
    r = rodauth_for_account
    r.create_api_key("CI server", expires_in: -1)

    assert_equal 0, r.send(:active_api_keys_ds).count
  end

  def test_create_api_key_tries_again_after_equal_digest
    api_keys = ["rak_#{"A" * 43}", "rak_#{"A" * 43}", "rak_#{"B" * 43}"]
    r = rodauth_for_account { generate_api_key { api_keys.shift } }

    assert_equal "rak_#{"A" * 43}", r.create_api_key("first")
    assert_equal "rak_#{"B" * 43}", r.create_api_key("second")
    assert_equal 2, r.send(:api_keys_ds).count
  end

  def test_create_api_key_raises_after_three_equal_digests
    r = rodauth_for_account { generate_api_key { "rak_#{"A" * 43}" } }
    r.create_api_key("first")

    assert_raises(Sequel::UniqueConstraintViolation) { r.create_api_key("second") }
    assert_nil r.created_api_key_id
    assert_equal 1, r.send(:api_keys_ds).count
  end

  def test_api_key_insert_hash_can_add_columns
    DB.alter_table(:account_api_keys) { add_column :note, String }
    r = rodauth_for_account do
      api_key_insert_hash { |*args| super(*args).merge(note: "added by app") }
    end
    r.create_api_key("CI server")

    assert_equal "added by app", created_row(r)[:note]
  end
end
