defmodule CreatorSignal.PlausibleSSO.Config do
  @moduledoc """
  Runtime configuration for Creator Signal's standalone ZITADEL OIDC integration.

  This feature deliberately does not use Plausible's Enterprise SSO modules,
  routes, tables or feature flags.
  """

  @config_key __MODULE__

  def enabled?, do: get(:enabled, false)
  def force_login?, do: enabled?() and get(:force_login, false)
  def allow_insecure_http?, do: get(:allow_insecure_http, false)

  def issuer, do: fetch!(:issuer)
  def client_id, do: fetch!(:client_id)
  def client_secret, do: get(:client_secret)
  def bootstrap_email, do: fetch!(:bootstrap_email)
  def required_role, do: get(:required_role, "platform:operator")

  def role_claim do
    get(:role_claim, "urn:zitadel:iam:org:project:roles")
  end

  def team_name, do: get(:team_name, "Creator Signal")
  def default_team_role, do: get(:default_team_role, :admin)
  def session_timeout_minutes, do: get(:session_timeout_minutes, 720)

  def scopes do
    configured = get(:scopes, ["openid", "profile", "email"])
    role_scope = "urn:zitadel:iam:org:project:role:#{required_role()}"

    configured
    |> List.wrap()
    |> Kernel.++([role_scope])
    |> Enum.uniq()
  end

  def redirect_uri do
    PlausibleWeb.Endpoint.url() <> "/creator-signal/sso/callback"
  end

  defp get(key, default \\ nil) do
    :plausible
    |> Application.get_env(@config_key, [])
    |> Keyword.get(key, default)
  end

  defp fetch!(key) do
    case get(key) do
      value when is_binary(value) and value != "" -> value
      _ -> raise "missing Creator Signal SSO configuration: #{key}"
    end
  end
end
