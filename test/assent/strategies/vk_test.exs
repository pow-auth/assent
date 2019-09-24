defmodule Assent.Strategy.VKTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.VK

  @users_response [
    %{
      "id" => 210_700_286,
      "first_name" => "Lindsay",
      "last_name" => "Stirling",
      "screen_name" => "lindseystirling",
      "photo_200" => "https://pp.userapi.com/c840637/v840637830/2d20e/wMuAZn-RFak.jpg",
      "verified" => 1
    }
  ]
  @user %{
    "email" => "lindsay.stirling@example.com",
    "first_name" => "Lindsay",
    "last_name" => "Stirling",
    "name" => "Lindsay Stirling",
    "nickname" => "lindseystirling",
    "uid" => "210700286",
    "image" => "https://pp.userapi.com/c840637/v840637830/2d20e/wMuAZn-RFak.jpg",
    "verified" => true
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = VK.authorize_url(config)
    assert url =~ "/authorize"
  end

  describe "callback/2" do
    setup %{config: config, bypass: bypass} do
      config = Keyword.put(config, :token_url, "http://localhost:#{bypass.port}/access_token")

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, [uri: "/access_token", params: %{"access_token" => "access_token", "email" => "lindsay.stirling@example.com"}], fn conn ->
        {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        assert params["scope"] == "email"
      end)

      expect_oauth2_user_request(bypass, %{"response" => @users_response}, [uri: "/method/users.get"], fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)

        assert conn.params["access_token"] == "access_token"
        assert conn.params["fields"] == "uid,first_name,last_name,photo_200,screen_name,verified"
        assert conn.params["v"] == "5.69"
        assert conn.params["access_token"] == "access_token"
      end)

      assert {:ok, %{user: user}} = VK.callback(config, params)
      assert user == @user
    end

    test "handles error", %{config: config, callback_params: params, bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, %Assent.RequestError{error: :unreachable}} = VK.callback(config, params)
    end
  end
end
