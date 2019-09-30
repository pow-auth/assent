defmodule Assent.Strategy.GitlabTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Gitlab

  @user_response %{
    "id" => "1574083",
    "name" => "Snoop Dogg",
    "username" => "snoopdogg",
    "email" => "snoopdogg@example.com",
    "location" => "...",
    "avatar_url" => "...",
    "web_url" => "...",
    "website_url" => "..."
  }
  @user %{
    "uid" => "1574083",
    "name" => "Snoop Dogg",
    "nickname" => "snoopdogg",
    "email" => "snoopdogg@example.com",
    "location" => "...",
    "image" => "...",
    "urls" => %{
      "web_url" => "...",
      "website_url" => "..."
    }
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Gitlab.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    expect_oauth2_access_token_request(bypass, [uri: "/oauth/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)
    expect_oauth2_user_request(bypass, @user_response, uri: "/api/v4/user")

    assert {:ok, %{user: user}} = Gitlab.callback(config, params)
    assert user == @user
  end
end
