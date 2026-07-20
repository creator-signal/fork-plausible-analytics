defmodule CreatorSignal.PlausibleSSO.ClaimsTest do
  use Plausible.DataCase

  alias CreatorSignal.PlausibleSSO.{Claims, Config}

  setup do
    patch_env(Config,
      enabled: true,
      issuer: "https://auth.example.test",
      client_id: "plausible",
      bootstrap_email: "owner@example.test",
      required_role: "platform:operator",
      role_claim: "urn:zitadel:iam:org:project:roles"
    )
  end

  test "authorises a verified operator from ZITADEL's role map" do
    claims = valid_claims()

    assert {:ok, identity} = Claims.authorise(claims)
    assert identity.subject == "user-123"
    assert identity.email == "operator@example.test"
    assert identity.name == "Test Operator"
  end

  test "rejects a user without the required platform role" do
    claims =
      valid_claims()
      |> put_in(["urn:zitadel:iam:org:project:roles"], %{"platform:viewer" => %{}})

    assert {:error, :missing_required_role} = Claims.authorise(claims)
  end

  test "rejects an unverified email" do
    assert {:error, :email_not_verified} =
             valid_claims()
             |> Map.put("email_verified", false)
             |> Claims.authorise()
  end

  defp valid_claims do
    %{
      "iss" => "https://auth.example.test",
      "sub" => "user-123",
      "email" => "Operator@Example.Test",
      "email_verified" => true,
      "given_name" => "Test",
      "family_name" => "Operator",
      "urn:zitadel:iam:org:project:roles" => %{"platform:operator" => %{"org-1" => "Org"}}
    }
  end
end
