defmodule CreatorSignal.PlausibleSSO.OIDC do
  @moduledoc false

  alias CreatorSignal.PlausibleSSO.Config

  @clock_skew_seconds 60
  @allowed_algorithms ["RS256"]

  @type discovery :: %{
          issuer: String.t(),
          authorization_endpoint: String.t(),
          token_endpoint: String.t(),
          jwks_uri: String.t()
        }

  @spec discovery() :: {:ok, discovery()} | {:error, term()}
  def discovery do
    issuer = normalise_issuer(Config.issuer())
    url = issuer <> "/.well-known/openid-configuration"

    with :ok <- validate_issuer_url(issuer),
         {:ok, document} <- get_json(url),
         :ok <- exact_value(document, "issuer", issuer, :issuer_mismatch),
         {:ok, authorization_endpoint} <- endpoint(document, "authorization_endpoint", issuer),
         {:ok, token_endpoint} <- endpoint(document, "token_endpoint", issuer),
         {:ok, jwks_uri} <- endpoint(document, "jwks_uri", issuer) do
      {:ok,
       %{
         issuer: issuer,
         authorization_endpoint: authorization_endpoint,
         token_endpoint: token_endpoint,
         jwks_uri: jwks_uri
       }}
    end
  end

  @spec authorization_url(discovery(), String.t(), String.t(), String.t()) :: String.t()
  def authorization_url(discovery, state, nonce, code_verifier) do
    params = %{
      "client_id" => Config.client_id(),
      "redirect_uri" => Config.redirect_uri(),
      "response_type" => "code",
      "scope" => Enum.join(Config.scopes(), " "),
      "state" => state,
      "nonce" => nonce,
      "code_challenge" => pkce_challenge(code_verifier),
      "code_challenge_method" => "S256"
    }

    discovery.authorization_endpoint <> "?" <> URI.encode_query(params)
  end

  @spec exchange(discovery(), String.t(), String.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def exchange(discovery, code, code_verifier, expected_nonce) do
    form = %{
      "grant_type" => "authorization_code",
      "code" => code,
      "client_id" => Config.client_id(),
      "redirect_uri" => Config.redirect_uri(),
      "code_verifier" => code_verifier
    }

    with {:ok, tokens} <- post_form(discovery.token_endpoint, form),
         {:ok, id_token} <- required_string(tokens, "id_token", :missing_id_token),
         {:ok, access_token} <- required_string(tokens, "access_token", :missing_access_token),
         {:ok, jwks} <- get_json(discovery.jwks_uri),
         {:ok, claims} <- verify_id_token(id_token, jwks, discovery.issuer),
         :ok <- validate_claims(claims, expected_nonce, access_token) do
      {:ok, claims}
    end
  end

  @spec validate_claims(map(), String.t(), String.t(), integer()) :: :ok | {:error, term()}
  def validate_claims(claims, expected_nonce, access_token, now \\ System.system_time(:second)) do
    with :ok <- exact_value(claims, "iss", normalise_issuer(Config.issuer()), :issuer_mismatch),
         :ok <- validate_audience(claims),
         :ok <- validate_expiry(claims, now),
         :ok <- validate_issued_at(claims, now),
         :ok <- secure_claim(claims, "nonce", expected_nonce, :nonce_mismatch),
         :ok <- validate_authorised_party(claims),
         :ok <- validate_access_token_hash(claims, access_token) do
      :ok
    end
  end

  def random_token(bytes \\ 32) do
    bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  def pkce_challenge(code_verifier) do
    code_verifier
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.url_encode64(padding: false)
  end

  defp verify_id_token(token, %{"keys" => keys}, issuer) when is_list(keys) do
    with {:ok, header} <- jwt_header(token),
         {:ok, kid} <- required_string(header, "kid", :missing_key_id),
         {:ok, algorithm} <- required_string(header, "alg", :missing_algorithm),
         :ok <- validate_algorithm(algorithm),
         {:ok, jwk} <- find_jwk(keys, kid, algorithm),
         {true, %JOSE.JWT{fields: claims}, _jws} <-
           JOSE.JWT.verify_strict(JOSE.JWK.from_map(jwk), [algorithm], token),
         :ok <- exact_value(claims, "iss", issuer, :issuer_mismatch) do
      {:ok, claims}
    else
      {false, _, _} -> {:error, :invalid_signature}
      {:error, _} = error -> error
      _ -> {:error, :invalid_id_token}
    end
  rescue
    _ -> {:error, :invalid_id_token}
  end

  defp verify_id_token(_, _, _), do: {:error, :invalid_jwks}

  defp validate_algorithm(algorithm) do
    if algorithm in @allowed_algorithms, do: :ok, else: {:error, :unsupported_algorithm}
  end

  defp jwt_header(token) do
    with [encoded_header, _claims, _signature] <- String.split(token, "."),
         {:ok, header_json} <- Base.url_decode64(encoded_header, padding: false),
         {:ok, header} when is_map(header) <- Jason.decode(header_json) do
      {:ok, header}
    else
      _ -> {:error, :invalid_id_token}
    end
  end

  defp find_jwk(keys, kid, algorithm) do
    case Enum.find(
           keys,
           &(Map.get(&1, "kid") == kid and Map.get(&1, "alg", algorithm) == algorithm)
         ) do
      nil -> {:error, :signing_key_not_found}
      jwk -> {:ok, jwk}
    end
  end

  defp validate_audience(%{"aud" => audience} = claims) do
    client_id = Config.client_id()
    audiences = if is_list(audience), do: audience, else: [audience]

    cond do
      client_id not in audiences ->
        {:error, :audience_mismatch}

      length(audiences) > 1 and Map.get(claims, "azp") != client_id ->
        {:error, :authorised_party_mismatch}

      true ->
        :ok
    end
  end

  defp validate_audience(_), do: {:error, :missing_audience}

  defp validate_authorised_party(%{"azp" => azp}) when is_binary(azp) do
    if azp == Config.client_id(), do: :ok, else: {:error, :authorised_party_mismatch}
  end

  defp validate_authorised_party(_), do: :ok

  defp validate_expiry(%{"exp" => expires_at}, now) when is_number(expires_at) do
    if expires_at + @clock_skew_seconds >= now, do: :ok, else: {:error, :expired_id_token}
  end

  defp validate_expiry(_, _), do: {:error, :missing_expiry}

  defp validate_issued_at(%{"iat" => issued_at}, now) when is_number(issued_at) do
    if issued_at <= now + @clock_skew_seconds, do: :ok, else: {:error, :invalid_issued_at}
  end

  defp validate_issued_at(_, _), do: {:error, :missing_issued_at}

  defp validate_access_token_hash(%{"at_hash" => expected}, access_token)
       when is_binary(expected) do
    actual =
      access_token
      |> then(&:crypto.hash(:sha256, &1))
      |> binary_part(0, 16)
      |> Base.url_encode64(padding: false)

    if secure_compare(actual, expected), do: :ok, else: {:error, :access_token_hash_mismatch}
  end

  defp validate_access_token_hash(_, _), do: :ok

  defp secure_claim(claims, key, expected, error) do
    case Map.get(claims, key) do
      actual when is_binary(actual) ->
        if secure_compare(actual, expected), do: :ok, else: {:error, error}

      _ ->
        {:error, error}
    end
  end

  defp secure_compare(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right) do
    Plug.Crypto.secure_compare(left, right)
  end

  defp secure_compare(_, _), do: false

  defp endpoint(document, key, issuer) do
    with {:ok, value} <- required_string(document, key, :invalid_discovery_document),
         :ok <- same_origin(value, issuer) do
      {:ok, value}
    end
  end

  defp same_origin(url, issuer) do
    endpoint_uri = URI.parse(url)
    issuer_uri = URI.parse(issuer)

    if {endpoint_uri.scheme, endpoint_uri.host, endpoint_uri.port} ==
         {issuer_uri.scheme, issuer_uri.host, issuer_uri.port} do
      :ok
    else
      {:error, :discovery_endpoint_origin_mismatch}
    end
  end

  defp validate_issuer_url(issuer) do
    uri = URI.parse(issuer)

    cond do
      uri.host in [nil, ""] -> {:error, :invalid_issuer}
      uri.query || uri.fragment -> {:error, :invalid_issuer}
      uri.scheme == "https" -> :ok
      uri.scheme == "http" and Config.allow_insecure_http?() -> :ok
      true -> {:error, :insecure_issuer}
    end
  end

  defp get_json(url) do
    request = Finch.build(:get, url, [{"accept", "application/json"}])

    with {:ok, %Finch.Response{status: status, body: body}} when status in 200..299 <-
           Finch.request(request, Plausible.Finch),
         {:ok, json} when is_map(json) <- Jason.decode(body) do
      {:ok, json}
    else
      {:ok, %Finch.Response{status: status}} -> {:error, {:http_status, status}}
      {:error, _} = error -> error
      _ -> {:error, :invalid_json_response}
    end
  end

  defp post_form(url, form) do
    headers =
      [{"accept", "application/json"}, {"content-type", "application/x-www-form-urlencoded"}]
      |> maybe_add_client_auth()

    request = Finch.build(:post, url, headers, URI.encode_query(form))

    with {:ok, %Finch.Response{status: status, body: body}} when status in 200..299 <-
           Finch.request(request, Plausible.Finch),
         {:ok, json} when is_map(json) <- Jason.decode(body) do
      {:ok, json}
    else
      {:ok, %Finch.Response{status: status}} -> {:error, {:token_endpoint_status, status}}
      {:error, _} = error -> error
      _ -> {:error, :invalid_token_response}
    end
  end

  defp maybe_add_client_auth(headers) do
    case Config.client_secret() do
      secret when is_binary(secret) and secret != "" ->
        credentials = Base.encode64(Config.client_id() <> ":" <> secret)
        [{"authorization", "Basic " <> credentials} | headers]

      _ ->
        headers
    end
  end

  defp exact_value(map, key, expected, error) do
    if Map.get(map, key) == expected, do: :ok, else: {:error, error}
  end

  defp required_string(map, key, error) do
    case Map.get(map, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  defp normalise_issuer(issuer), do: String.trim_trailing(issuer, "/")
end
