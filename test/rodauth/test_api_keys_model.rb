# frozen_string_literal: true

require "test_helper"

class Rodauth::TestApiKeysModel < RodauthTestCase
  def teardown
    Object.send(:remove_const, :Account) if defined?(Account)
  end

  # Make an account model with rodauth-model. The association needs a constant name.
  def account_model
    model = Class.new(Sequel::Model)
    model.set_dataset(DB[:accounts])
    Object.const_set(:Account, model)
    model.include Rodauth::Model(app.rodauth)
    model
  end

  def create_key(account_id, name)
    r = app.rodauth.allocate
    r.account_from_id(account_id)
    r.create_api_key(name)
  end

  def test_model_association
    rodauth_app { enable :api_keys }
    account_id = create_account
    other_account_id = create_account(login: "bar@example.com")
    create_key(account_id, "first")
    create_key(account_id, "second")
    create_key(other_account_id, "other")

    api_keys = account_model.with_pk(account_id).api_keys_dataset.order(:id)

    assert_equal ["first", "second"], api_keys.map(&:name)
    assert_equal account_id, api_keys.first.account.id
  end

  def test_model_destroy_removes_api_keys
    rodauth_app { enable :api_keys }
    # An account without a password. The model of this app does not remove password rows.
    account_id = DB[:accounts].insert(email: LOGIN, status_id: 2)
    create_key(account_id, "first")

    account_model.with_pk(account_id).destroy

    assert_equal 0, DB[:account_api_keys].where(account_id: account_id).count
  end
end
