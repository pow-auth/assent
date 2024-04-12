defmodule Assent.Strategy.BitbucketTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Bitbucket

  @user_response %{
    "account_id" => "8675309",
    "account_status" => "active",
    "created_on" => "2023-03-17T03:27:21.528051+00:00",
    "display_name" => "Johnny O",
    "has_2fa_enabled" => nil,
    "is_staff" => false,
    "location" => nil,
    "nickname" => "Johnny O",
    "type" => "user",
    "username" => "djgoku",
    "uuid" => "{1bf26c46-c29b-4fc0-bda2-e5c5f1adde19}"
  }
  @user %{
    "sub" => "8675309",
    "display_name" => "Johnny O",
    "nickname" => "Johnny O",
    "username" => "djgoku",
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Bitbucket.authorize_url(config)
    assert url =~ "/oauth2/authorize?client_id="
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :token_url, TestServer.url("/site/oauth2/access_token"))

      {:ok, config: config}
    end

    test "callback/2", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request([uri: "/site/oauth2/access_token"], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)

      expect_oauth2_user_request(@user_response, uri: "/2.0/user")

      assert {:ok, %{user: user}} = Bitbucket.callback(config, params)
      # assert user == @user
    end
  end
end
