defmodule CreatorSignal.PlausibleSSO.Provisioner do
  @moduledoc false

  import Ecto.Query

  alias CreatorSignal.PlausibleSSO.{Claims, Config, Identity, Settings}
  alias Plausible.{Auth, Repo, Teams}

  @settings_key "default"
  @advisory_lock_key 1_129_491_675

  @spec provision(map()) ::
          {:ok, %{user: Auth.User.t(), team: Teams.Team.t()}}
          | {:error, term()}
  def provision(claims) do
    with {:ok, identity_attrs} <- Claims.authorise(claims) do
      Repo.transaction(fn ->
        Repo.query!("SELECT pg_advisory_xact_lock($1)", [@advisory_lock_key])
        do_provision(identity_attrs)
      end)
      |> unwrap_transaction()
    end
  end

  def local_login_allowed?(%Auth.User{} = user) do
    if Identity.externally_managed?(user), do: {:error, :external_identity}, else: :ok
  end

  def session_options(%Auth.User{} = user) do
    if Identity.externally_managed?(user) do
      timeout_at =
        NaiveDateTime.add(
          NaiveDateTime.utc_now(:second),
          Config.session_timeout_minutes(),
          :minute
        )

      [timeout_at: timeout_at]
    else
      []
    end
  end

  defp do_provision(attrs) do
    case Repo.one(
           from(i in Identity,
             where: i.issuer == ^attrs.issuer and i.subject == ^attrs.subject,
             preload: [:user]
           )
         ) do
      %Identity{user: user} = identity ->
        user = sync_user!(identity, user, attrs)
        team = configured_team!()
        ensure_membership!(team, user)
        %{user: user, team: team}

      nil ->
        user = find_or_create_user!(attrs)
        team = configured_or_bootstrap_team!(user, attrs)
        ensure_membership!(team, user)

        %Identity{}
        |> Identity.changeset(%{
          issuer: attrs.issuer,
          subject: attrs.subject,
          user_id: user.id
        })
        |> Repo.insert!()

        %{user: user, team: team}
    end
  end

  defp find_or_create_user!(attrs) do
    case Repo.get_by(Auth.User, email: attrs.email) do
      nil ->
        password =
          64
          |> :crypto.strong_rand_bytes()
          |> Base.url_encode64(padding: false)

        %{email: attrs.email, name: attrs.name, password: password}
        |> Auth.User.new()
        |> Ecto.Changeset.put_change(:email_verified, true)
        |> Repo.insert!()

      user ->
        if Identity.externally_managed?(user) do
          Repo.rollback(:email_already_linked)
        else
          user
        end
    end
  end

  defp sync_user!(identity, user, attrs) do
    if identity.issuer != attrs.issuer or identity.subject != attrs.subject do
      Repo.rollback(:identity_mismatch)
    end

    user
    |> Auth.User.changeset(%{email: attrs.email, name: attrs.name, email_verified: true})
    |> Repo.update!()
  end

  defp configured_or_bootstrap_team!(user, attrs) do
    case Repo.get(Settings, @settings_key) do
      %Settings{} ->
        configured_team!()

      nil ->
        if String.downcase(attrs.email) == String.downcase(Config.bootstrap_email()) do
          bootstrap_team!(user)
        else
          Repo.rollback(:bootstrap_user_required)
        end
    end
  end

  defp bootstrap_team!(user) do
    team =
      case Teams.get_by_owner(user) do
        {:ok, team} ->
          team

        {:error, :no_team} ->
          case Teams.get_or_create(user) do
            {:ok, team} -> team
            {:error, reason} -> Repo.rollback(reason)
          end

        {:error, :multiple_teams} ->
          Repo.rollback(:multiple_owned_teams)
      end

    team =
      team
      |> Teams.Team.name_changeset(%{name: Config.team_name()})
      |> Repo.update!()
      |> Teams.complete_setup()

    %Settings{}
    |> Settings.changeset(%{key: @settings_key, team_id: team.id})
    |> Repo.insert!()

    team
  end

  defp configured_team! do
    case Repo.get(Settings, @settings_key) |> Repo.preload(:team) do
      %Settings{team: %Teams.Team{} = team} -> team
      _ -> Repo.rollback(:sso_team_not_configured)
    end
  end

  defp ensure_membership!(team, user) do
    role = Config.default_team_role()
    now = NaiveDateTime.utc_now(:second)

    case Teams.Invitations.create_team_membership(team, role, user, now) do
      {:ok, _membership} -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp unwrap_transaction({:ok, result}), do: {:ok, result}
  defp unwrap_transaction({:error, reason}), do: {:error, reason}
end
