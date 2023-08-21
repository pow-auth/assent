defmodule Assent.Strategy.SpotifyTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Spotify

  # From https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile
  # but with some test data added
  @user_response %{
    "display_name" => "nick",
    "email" => "username@example.org",
    "external_urls" => %{"spotify" => "https://open.spotify.com/user/username"},
    "followers" => %{"href" => nil, "total" => 1},
    "href" => "https://api.spotify.com/v1/users/username",
    "id" => "username",
    "images" => [
      %{
        "height" => 64,
        "url" => "https://i.scdn.co/image/ab67616d00001e02ff9ca10b55ce82ae553c8228",
        "width" => 64
      },
      %{
        "height" => 300,
        "url" => "https://i.scdn.co/image/ab67616d00001e02ff9ca10b55ce82ae553c8228",
        "width" => 300
      }
    ],
    "type" => "user",
    "uri" => "spotify:user:username"
  }
  @user %{
    "sub" => "username",
    "email" => "username@example.org",
    "picture" => "https://i.scdn.co/image/ab67616d00001e02ff9ca10b55ce82ae553c8228",
    "preferred_username" => "nick",
    "name" => "nick"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Spotify.authorize_url(config)
    assert url =~ "https://accounts.spotify.com/authorize?client_id="
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :token_url, TestServer.url("/api/token"))

      {:ok, config: config}
    end

    test "callback/2", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request([uri: "/api/token"], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)

      expect_oauth2_user_request(@user_response, uri: "/me")

      assert {:ok, %{user: user}} = Spotify.callback(config, params)
      assert user == @user
    end
  end
end
