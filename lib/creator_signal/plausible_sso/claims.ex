defmodule CreatorSignal.PlausibleSSO.Claims do
  @moduledoc false

  alias CreatorSignal.PlausibleSSO.Config

  @type identity :: %{
          issuer: String.t(),
          subject: String.t(),
          email: String.t(),
          name: String.t()
        }

  @spec authorise(map()) :: {:ok, identity()} | {:error, atom()}
  def authorise(claims) when is_map(claims) do
    with {:ok, issuer} <- required_string(claims, "iss", :missing_issuer),
         {:ok, subject} <- required_string(claims, "sub", :missing_subject),
         {:ok, email} <- required_string(claims, "email", :missing_email),
         :ok <- email_verified(claims),
         :ok <- required_role(claims),
         {:ok, name} <- display_name(claims) do
      {:ok,
       %{
         issuer: issuer,
         subject: subject,
         email: String.downcase(email),
         name: name
       }}
    end
  end

  def authorise(_), do: {:error, :invalid_claims}

  @spec has_role?(term(), String.t()) :: boolean()
  def has_role?(roles, required_role) when is_map(roles) do
    Map.has_key?(roles, required_role) or
      Enum.any?(Map.values(roles), &has_role?(&1, required_role))
  end

  def has_role?(roles, required_role) when is_list(roles) do
    Enum.any?(roles, &has_role?(&1, required_role))
  end

  def has_role?(role, required_role) when is_binary(role) do
    role == required_role or required_role in String.split(role, [",", " "], trim: true)
  end

  def has_role?(_, _), do: false

  defp required_role(claims) do
    role_claim = Config.role_claim()
    required_role = Config.required_role()

    if has_role?(Map.get(claims, role_claim), required_role) do
      :ok
    else
      {:error, :missing_required_role}
    end
  end

  defp email_verified(%{"email_verified" => value}) when value in [true, "true"], do: :ok
  defp email_verified(_), do: {:error, :email_not_verified}

  defp display_name(claims) do
    case Map.get(claims, "name") do
      name when is_binary(name) and name != "" ->
        {:ok, name}

      _ ->
        name =
          [Map.get(claims, "given_name"), Map.get(claims, "family_name")]
          |> Enum.filter(&(is_binary(&1) and &1 != ""))
          |> Enum.join(" ")

        if name == "", do: {:error, :missing_name}, else: {:ok, name}
    end
  end

  defp required_string(map, key, error) do
    case Map.get(map, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end
end
