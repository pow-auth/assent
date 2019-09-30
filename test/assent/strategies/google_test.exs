defmodule Assent.Strategy.GoogleTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Google

  @user_response %{
    "id" => "1",
    "email" => "foo@example.com",
    "verified_email" => true,
    "name" => "Dan Schultzer",
    "given_name" => "Dan",
    "family_name" => "Schultzer",
    "link" => "https://example.com/profile",
    "picture" => "https://example.com/images/profile.jpg",
    "locale" => "en-US",
    "hd" => "example.com"
  }
  @user  %{
    "email" => "foo@example.com",
    "image" => "https://example.com/images/profile.jpg",
    "name" => "Dan Schultzer",
    "first_name" => "Dan",
    "last_name" => "Schultzer",
    "domain" => "example.com",
    "uid" => "1",
    "urls" => %{"Google" => "https://example.com/profile"}
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Google.authorize_url(config)
    assert url =~ "https://accounts.google.com/o/oauth2/v2/auth?client_id="
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    expect_oauth2_access_token_request(bypass, [uri: "/oauth2/v4/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)
    expect_oauth2_user_request(bypass, @user_response, uri: "/oauth2/v2/userinfo")

    assert {:ok, %{user: user}} = Google.callback(config, params)
    assert user == @user
  end
end
