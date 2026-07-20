defmodule CreatorSignal.PlausibleSSO.OIDCTest do
  use Plausible.DataCase

  alias CreatorSignal.PlausibleSSO.{Config, OIDC}

  setup do
    patch_env(Config,
      enabled: true,
      issuer: "https://auth.example.test",
      client_id: "plausible-client",
      bootstrap_email: "owner@example.test"
    )
  end

  test "validates issuer, audience, expiry, issued-at, nonce and access-token hash" do
    now = 1_800_000_000
    access_token = "access-token"
    nonce = "expected-nonce"

    claims = %{
      "iss" => "https://auth.example.test",
      "aud" => "plausible-client",
      "exp" => now + 300,
      "iat" => now,
      "nonce" => nonce,
      "at_hash" => access_token_hash(access_token)
    }

    assert :ok = OIDC.validate_claims(claims, nonce, access_token, now)
  end

  test "rejects an expired ID token" do
    now = 1_800_000_000

    claims = %{
      "iss" => "https://auth.example.test",
      "aud" => "plausible-client",
      "exp" => now - 61,
      "iat" => now - 300,
      "nonce" => "nonce"
    }

    assert {:error, :expired_id_token} = OIDC.validate_claims(claims, "nonce", "token", now)
  end

  test "rejects a mismatched audience" do
    now = 1_800_000_000

    claims = %{
      "iss" => "https://auth.example.test",
      "aud" => "another-client",
      "exp" => now + 300,
      "iat" => now,
      "nonce" => "nonce"
    }

    assert {:error, :audience_mismatch} = OIDC.validate_claims(claims, "nonce", "token", now)
  end

  test "rejects a mismatched nonce" do
    now = 1_800_000_000

    claims = %{
      "iss" => "https://auth.example.test",
      "aud" => "plausible-client",
      "exp" => now + 300,
      "iat" => now,
      "nonce" => "wrong"
    }

    assert {:error, :nonce_mismatch} = OIDC.validate_claims(claims, "expected", "token", now)
  end

  defp access_token_hash(access_token) do
    access_token
    |> then(&:crypto.hash(:sha256, &1))
    |> binary_part(0, 16)
    |> Base.url_encode64(padding: false)
  end
end
