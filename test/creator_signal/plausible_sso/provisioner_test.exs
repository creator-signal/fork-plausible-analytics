defmodule CreatorSignal.PlausibleSSO.ProvisionerTest do
  use Plausible.DataCase

  import Ecto.Query

  alias CreatorSignal.PlausibleSSO.{Config, Identity, Provisioner, Settings}
  alias Plausible.{Auth, Repo, Teams}

  setup do
    patch_env(Config,
      enabled: true,
      issuer: "https://auth.example.test",
      client_id: "plausible-client",
      bootstrap_email: "owner@example.test",
      required_role: "platform:operator",
      role_claim: "urn:zitadel:iam:org:project:roles",
      team_name: "Creator Signal",
      default_team_role: :admin,
      session_timeout_minutes: 720
    )
  end

  test "the configured bootstrap operator creates and owns the SSO team" do
    assert {:ok, %{user: user, team: team}} = Provisioner.provision(claims("owner@example.test"))

    assert user.email_verified
    assert team.name == "Creator Signal"
    assert team.setup_complete
    assert Repo.get_by!(Teams.Membership, user_id: user.id, team_id: team.id).role == :owner
    assert Repo.get!(Settings, "default").team_id == team.id
    assert Repo.get_by!(Identity, user_id: user.id).subject == "subject-owner@example.test"
    refute Provisioner.local_login_allowed?(user) == :ok
  end

  test "a non-bootstrap operator cannot initialise the team" do
    assert {:error, :bootstrap_user_required} =
             Provisioner.provision(claims("other@example.test"))

    refute Repo.get_by(Auth.User, email: "other@example.test")
  end

  test "later authorised operators are provisioned as administrators" do
    assert {:ok, %{team: team}} = Provisioner.provision(claims("owner@example.test"))
    assert {:ok, %{user: user, team: ^team}} = Provisioner.provision(claims("admin@example.test"))

    membership = Repo.get_by!(Teams.Membership, user_id: user.id, team_id: team.id)
    assert membership.role == :admin
  end

  test "linked user sessions have a fixed timeout that activity does not extend" do
    assert {:ok, %{user: user}} = Provisioner.provision(claims("owner@example.test"))

    now = ~N[2026-07-21 00:00:00]
    timeout_at = NaiveDateTime.add(now, 720, :minute)

    session =
      user
      |> Plausible.Auth.UserSession.new_session("test", now: now, timeout_at: timeout_at)
      |> Ecto.Changeset.apply_changes()
      |> Plausible.Auth.UserSession.touch_session(NaiveDateTime.add(now, 60, :minute))
      |> Ecto.Changeset.apply_changes()

    assert session.timeout_at == timeout_at
  end

  test "a missing role is rejected before any user is provisioned" do
    unauthorised =
      claims("owner@example.test")
      |> Map.put("urn:zitadel:iam:org:project:roles", %{"platform:viewer" => %{}})

    assert {:error, :missing_required_role} = Provisioner.provision(unauthorised)
    assert Repo.aggregate(from(u in Auth.User), :count) == 0
  end

  defp claims(email) do
    %{
      "iss" => "https://auth.example.test",
      "sub" => "subject-#{email}",
      "email" => email,
      "email_verified" => true,
      "name" => "Test Operator",
      "urn:zitadel:iam:org:project:roles" => %{"platform:operator" => %{}}
    }
  end
end
