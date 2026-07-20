defmodule CreatorSignal.PlausibleSSO.ControllerTest do
  use PlausibleWeb.ConnCase

  alias CreatorSignal.PlausibleSSO.Config

  test "standalone login route is unavailable when disabled", %{conn: conn} do
    patch_env(Config, enabled: false)

    conn = get(conn, "/creator-signal/sso/login")

    assert response(conn, 404) == "Not found"
  end
end
