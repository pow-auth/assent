defmodule Assent.Strategy.InstagramTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.{Strategy.Instagram, TestServer}

  # From https://developers.facebook.com/docs/instagram-basic-display-api/reference/user
  @user_response %{
    "id" => "17841405793187218",
    "username" => "jayposiris"
  }
  @user %{
    "preferred_username" => "jayposiris",
    "sub" => "17841405793187218"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Instagram.authorize_url(config)
    assert url =~ "https://api.instagram.com/oauth/authorize?client_id="
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :token_url, TestServer.url("/oauth/access_token"))

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request([uri: "/oauth/access_token", params: %{access_token: "access_token", user: @user_response}], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)

      expect_oauth2_user_request(@user_response, [uri: "/me"], fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)

        assert conn.params["access_token"] == "access_token"
        assert conn.params["fields"] == "id,username"
      end)

      assert {:ok, %{user: user}} = Instagram.callback(config, params)
      assert user == @user
    end

    test "handles error", %{config: config, callback_params: params} do
      TestServer.down()

      assert {:error, %Assent.RequestError{error: :unreachable}} = Instagram.callback(config, params)
    end
  end
end
