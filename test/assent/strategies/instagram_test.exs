defmodule Assent.Strategy.InstagramTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Instagram

  # From https://developers.facebook.com/docs/instagram-basic-display-api/reference/user
  @user_response %{
    "id" => "17841405793187218",
    "username" => "jayposiris"
  }
  @user %{
    "preferred_username" => "jayposiris",
    "sub" => "17841405793187218"
  }

  test "authorize_url/1", %{config: config} do
    assert {:ok, %{url: url}} = Instagram.authorize_url(config)
    assert url =~ "https://api.instagram.com/oauth/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params} do
    config = Keyword.put(config, :token_url, TestServer.url("/oauth/access_token"))

    expect_oauth2_access_token_request(
      [
        uri: "/oauth/access_token",
        params: %{access_token: "access_token", user: @user_response}
      ],
      fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end
    )

    expect_oauth2_user_request(@user_response, [uri: "/me"], fn conn ->
      conn = Plug.Conn.fetch_query_params(conn)

      assert conn.params["access_token"] == "access_token"
      assert conn.params["fields"] == "id,username"
    end)

    assert {:ok, %{user: user}} = Instagram.callback(config, params)
    assert user == @user
  end
end
