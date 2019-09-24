defmodule Assent.Strategy.FacebookTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Facebook

  @user_response %{name: "Dan Schultzer", email: "foo@example.com", id: "1"}
  @user %{
    "email" => "foo@example.com",
    "name" => "Dan Schultzer",
    "uid" => "1",
    "urls" => %{}
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Facebook.authorize_url(config)
    assert url =~ "https://www.facebook.com/v2.12/dialog/oauth?client_id="
  end

  describe "callback/2" do
    test "normalizes data", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, [uri: "/oauth/access_token"], fn conn ->
        {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        assert params["scope"] == "email"
        assert params["redirect_uri"] == "test"
      end)

      expect_oauth2_user_request(bypass, @user_response, [uri: "/me"], fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)

        assert conn.params["access_token"] == "access_token"
        assert conn.params["fields"] == "name,email"
        assert conn.params["appsecret_proof"] == Base.encode16(:crypto.hmac(:sha256, "secret", "access_token"), case: :lower)
      end)

      assert {:ok, %{user: user}} = Facebook.callback(config, params)
      assert user == Map.put(@user, "image", "http://localhost:#{bypass.port}/1/picture")
    end

    test "handles error", %{config: config, callback_params: params, bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, %Assent.RequestError{error: :unreachable}} = Facebook.callback(config, params)
    end
  end
end
