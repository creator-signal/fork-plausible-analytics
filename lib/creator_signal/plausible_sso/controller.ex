defmodule CreatorSignal.PlausibleSSO.Controller do
  @moduledoc false

  use PlausibleWeb, :controller

  require Logger

  alias CreatorSignal.PlausibleSSO.{Config, OIDC, Provisioner}
  alias PlausibleWeb.UserAuth

  @session_prefix "creator_signal_sso_"

  def login(conn, params) do
    if Config.enabled?() do
      state = OIDC.random_token()
      nonce = OIDC.random_token()
      verifier = OIDC.random_token(64)
      return_to = safe_return_to(params["return_to"])

      case OIDC.discovery() do
        {:ok, discovery} ->
          url = OIDC.authorization_url(discovery, state, nonce, verifier)

          conn
          |> put_session(session_key("state"), state)
          |> put_session(session_key("nonce"), nonce)
          |> put_session(session_key("verifier"), verifier)
          |> put_session(session_key("return_to"), return_to)
          |> redirect(external: url)

        {:error, reason} ->
          fail(conn, reason)
      end
    else
      send_resp(conn, 404, "Not found")
    end
  end

  def callback(conn, %{"error" => error} = params) do
    fail(conn, {:provider_error, error, params["error_description"]})
  end

  def callback(conn, %{"code" => code, "state" => state}) do
    with :ok <- ensure_enabled(),
         {:ok, expected_state} <- session_value(conn, "state"),
         true <- secure_compare(state, expected_state) or {:error, :state_mismatch},
         {:ok, nonce} <- session_value(conn, "nonce"),
         {:ok, verifier} <- session_value(conn, "verifier"),
         {:ok, discovery} <- OIDC.discovery(),
         {:ok, claims} <- OIDC.exchange(discovery, code, verifier, nonce),
         {:ok, %{user: user, team: team}} <- Provisioner.provision(claims) do
      return_to = get_session(conn, session_key("return_to"))

      conn
      |> clear_flow()
      |> UserAuth.log_in_user(user, safe_return_to(return_to))
      |> put_session("current_team_id", team.identifier)
    else
      {:error, reason} -> fail(conn, reason)
      false -> fail(conn, :invalid_callback)
    end
  end

  def callback(conn, _params), do: fail(conn, :invalid_callback)

  defp ensure_enabled do
    if Config.enabled?(), do: :ok, else: {:error, :disabled}
  end

  defp fail(conn, reason) do
    Logger.warning("Creator Signal SSO login failed: #{inspect(reason)}")

    conn = clear_flow(conn)

    if Plausible.Release.should_be_first_launch?() do
      conn
      |> put_status(401)
      |> text(user_message(reason))
    else
      conn
      |> put_flash(:login_error, user_message(reason))
      |> redirect(to: "/login?local=true")
    end
  end

  defp user_message(:missing_required_role),
    do: "Your Creator Signal account is not authorised to access Plausible."

  defp user_message(:bootstrap_user_required),
    do: "The configured Creator Signal bootstrap operator must sign in first."

  defp user_message(_),
    do: "Creator Signal sign-in failed. Please try again or contact the platform administrator."

  defp session_value(conn, suffix) do
    case get_session(conn, session_key(suffix)) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :missing_login_session}
    end
  end

  defp clear_flow(conn) do
    Enum.reduce(["state", "nonce", "verifier", "return_to"], conn, fn suffix, acc ->
      delete_session(acc, session_key(suffix))
    end)
  end

  defp session_key(suffix), do: @session_prefix <> suffix

  defp safe_return_to(path) when is_binary(path) do
    if String.starts_with?(path, "/") and not String.starts_with?(path, "//"), do: path, else: nil
  end

  defp safe_return_to(_), do: nil

  defp secure_compare(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right) do
    Plug.Crypto.secure_compare(left, right)
  end

  defp secure_compare(_, _), do: false
end
