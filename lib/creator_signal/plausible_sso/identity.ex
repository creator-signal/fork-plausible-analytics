defmodule CreatorSignal.PlausibleSSO.Identity do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  schema "creator_signal_sso_identities" do
    field :issuer, :string
    field :subject, :string

    belongs_to :user, Plausible.Auth.User

    timestamps()
  end

  def changeset(identity \\ %__MODULE__{}, attrs) do
    identity
    |> cast(attrs, [:issuer, :subject, :user_id])
    |> validate_required([:issuer, :subject, :user_id])
    |> unique_constraint([:issuer, :subject])
    |> unique_constraint(:user_id)
  end

  def externally_managed?(%Plausible.Auth.User{id: user_id}) do
    Plausible.Repo.exists?(from(i in __MODULE__, where: i.user_id == ^user_id))
  end

  def externally_managed?(_), do: false
end
