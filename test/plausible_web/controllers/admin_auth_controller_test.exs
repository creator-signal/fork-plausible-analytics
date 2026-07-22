defmodule PlausibleWeb.AdminAuthControllerTest do
  use PlausibleWeb.ConnCase
  alias Plausible.Release

  describe "GET /" do
    @describetag :ce_build_only
    test "disable registration", %{conn: conn} do
      insert(:user)
      patch_config(disable_registration: true)
      conn = get(conn, "/register")
      assert redirected_to(conn) == "/login"

      assert Phoenix.Flash.get(conn.assigns.flash, :error) ==
               "Registration is disabled on this instance"
    end

    test "disabled registration redirects to forced Creator Signal SSO without an error flash", %{
      conn: conn
    } do
      insert(:user)
      patch_config(disable_registration: true)
      patch_env(CreatorSignal.PlausibleSSO.Config, enabled: true, force_login: true)

      conn = get(conn, "/register")

      assert redirected_to(conn) == "/creator-signal/sso/login"
      refute Phoenix.Flash.get(conn.assigns.flash, :error)
    end

    test "disable registration + first launch", %{conn: conn} do
      patch_config(disable_registration: true)
      assert Release.should_be_first_launch?()

      # "first launch" takes precedence
      conn = get(conn, "/register")
      assert html_response(conn, 200) =~ "Create your Plausible CE account"
    end
  end

  def patch_config(config) do
    updated_config = Keyword.merge([disable_registration: false], config)
    patch_env(:selfhost, updated_config)
  end
end
