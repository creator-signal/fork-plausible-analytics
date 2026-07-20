defmodule CreatorSignal.PlausibleSSO.Settings do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:key, :string, autogenerate: false}
  schema "creator_signal_sso_settings" do
    belongs_to :team, Plausible.Teams.Team

    timestamps()
  end

  def changeset(settings \\ %__MODULE__{}, attrs) do
    settings
    |> cast(attrs, [:key, :team_id])
    |> validate_required([:key, :team_id])
    |> unique_constraint(:key)
  end
end
