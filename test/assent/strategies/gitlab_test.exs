defmodule Assent.Strategy.GitlabTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Gitlab

  # From https://docs.gitlab.com/ee/api/users.html#list-current-user-for-normal-users
  @user_response %{
    "id" => 1,
    "username" => "john_smith",
    "email" => "john@example.com",
    "name" => "John Smith",
    "state" => "active",
    "avatar_url" => "http://localhost:3000/uploads/user/avatar/1/index.jpg",
    "web_url" => "http://localhost:3000/john_smith",
    "created_at" => "2012-05-23T08:00:58Z",
    "bio" => nil,
    "location" => nil,
    "public_email" => "john@example.com",
    "skype" => "",
    "linkedin" => "",
    "twitter" => "",
    "website_url" => "",
    "organization" => "",
    "last_sign_in_at" => "2012-06-01T11:41:01Z",
    "confirmed_at" => "2012-05-23T09:05:22Z",
    "theme_id" => 1,
    "last_activity_on" => "2012-05-23",
    "color_scheme_id" => 2,
    "projects_limit" => 100,
    "current_sign_in_at" => "2012-06-02T06:36:55Z",
    "identities" => [
      %{"provider" => "github", "extern_uid" => "2435223452345"},
      %{"provider" => "bitbucket", "extern_uid" => "john_smith"},
      %{"provider" => "google_oauth2", "extern_uid" => "8776128412476123468721346"}
    ],
    "can_create_group" => true,
    "can_create_project" => true,
    "two_factor_enabled" => true,
    "external" => false,
    "private_profile" => false
  }
  @user %{
    "email" => "john@example.com",
    "email_verified" => true,
    "name" => "John Smith",
    "picture" => "http://localhost:3000/uploads/user/avatar/1/index.jpg",
    "preferred_username" => "john_smith",
    "sub" => 1
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Gitlab.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params} do
    expect_oauth2_access_token_request([uri: "/oauth/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)
    expect_oauth2_user_request(@user_response, uri: "/api/v4/user")

    assert {:ok, %{user: user}} = Gitlab.callback(config, params)
    assert user == @user
  end
end
