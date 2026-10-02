# frozen_string_literal: true

# Test schema. It contains the Rodauth base tables and the API keys table.
Sequel.migration do
  change do
    create_table(:account_statuses) do
      Integer :id, primary_key: true
      String :name, null: false, unique: true
    end
    from(:account_statuses).import([:id, :name], [[1, "Unverified"], [2, "Verified"], [3, "Closed"]])

    create_table(:accounts) do
      primary_key :id, type: :Bignum
      foreign_key :status_id, :account_statuses, null: false, default: 1
      String :email, null: false
      index :email, unique: true
    end

    create_table(:account_password_hashes) do
      foreign_key :id, :accounts, primary_key: true, type: :Bignum
      String :password_hash, null: false
    end

    # Tables of other Rodauth features. Tests check that these features work with API keys.
    create_table(:account_remember_keys) do
      foreign_key :id, :accounts, primary_key: true, type: :Bignum
      String :key, null: false
      DateTime :deadline, null: false
    end

    create_table(:account_active_session_keys) do
      foreign_key :account_id, :accounts, type: :Bignum
      String :session_id
      Time :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      Time :last_use, null: false, default: Sequel::CURRENT_TIMESTAMP
      primary_key [:account_id, :session_id]
    end

    create_table(:account_session_keys) do
      foreign_key :id, :accounts, primary_key: true, type: :Bignum
      String :key, null: false
    end

    create_table(:account_verification_keys) do
      foreign_key :id, :accounts, primary_key: true, type: :Bignum
      String :key, null: false
      DateTime :requested_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :email_last_sent, null: false, default: Sequel::CURRENT_TIMESTAMP
    end

    create_table(:account_api_keys) do
      primary_key :id, type: :Bignum
      foreign_key :account_id, :accounts, type: :Bignum, null: false
      String :name, null: false
      String :digest, null: false, unique: true
      String :hint, null: false
      String :scopes
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
      DateTime :last_use
      DateTime :expires_at
      DateTime :revoked_at
      index [:account_id, :revoked_at]
    end
  end
end
