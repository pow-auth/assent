defmodule Assent.Strategy.GoogleTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Google

  # From https://www.oauth.com/oauth2-servers/signing-in-with-google/verifying-the-user-info/
  @user_response %{
    "sub" => "110248495921238986420",
    "name" => "Aaron Parecki",
    "given_name" => "Aaron",
    "family_name" => "Parecki",
    "picture" =>
      "https://lh4.googleusercontent.com/-kw-iMgD_j34/AAAAAAAAAAI/AAAAAAAAAAc/P1YY91tzesU/photo.jpg",
    "email" => "aaron.parecki@okta.com",
    "email_verified" => true,
    "locale" => "en",
    "hd" => "okta.com"
  }
  @user %{
    "email" => "aaron.parecki@okta.com",
    "email_verified" => true,
    "family_name" => "Parecki",
    "given_name" => "Aaron",
    "google_hd" => "okta.com",
    "name" => "Aaron Parecki",
    "locale" => "en",
    "picture" =>
      "https://lh4.googleusercontent.com/-kw-iMgD_j34/AAAAAAAAAAI/AAAAAAAAAAc/P1YY91tzesU/photo.jpg",
    "sub" => "110248495921238986420"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Google.authorize_url(config)
    assert url =~ "https://accounts.google.com/o/oauth2/v2/auth?client_id="
  end

  test "callback/2", %{config: config, callback_params: params} do
    expect_oauth2_access_token_request([uri: "/oauth2/v4/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)

    expect_oauth2_user_request(@user_response, uri: "/oauth2/v3/userinfo")

    assert {:ok, %{user: user}} = Google.callback(config, params)
    assert user == @user
  end
end
