defmodule Plausible.Repo.Migrations.AddCreatorSignalSSO do
  use Ecto.Migration

  def change do
    create table(:creator_signal_sso_identities) do
      add :issuer, :text, null: false
      add :subject, :text, null: false
      add :user_id, references(:users, on_delete: :delete_all), null: false

      timestamps()
    end

    create unique_index(:creator_signal_sso_identities, [:issuer, :subject])
    create unique_index(:creator_signal_sso_identities, [:user_id])

    create table(:creator_signal_sso_settings, primary_key: false) do
      add :key, :text, primary_key: true
      add :team_id, references(:teams, on_delete: :delete_all), null: false

      timestamps()
    end

    create unique_index(:creator_signal_sso_settings, [:team_id])
  end
end
