defmodule Assent.Strategy.InstagramTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Instagram

  @user_response %{
    "id" => "1574083",
    "username" => "snoopdogg",
    "full_name" => "Snoop Dogg",
    "profile_picture" => "..."
  }
  @user %{
    "image" => "...",
    "name" => "Snoop Dogg",
    "nickname" => "snoopdogg",
    "uid" => "1574083"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Instagram.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id="
  end

  describe "callback/2" do
    test "normalizes data", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, [uri: "/oauth/token", params: %{access_token: "access_token", user: @user_response}], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)

      assert {:ok, %{user: user}} = Instagram.callback(config, params)
      assert user == @user
    end

    test "handles error", %{config: config, callback_params: params, bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, %Assent.RequestError{error: :unreachable}} = Instagram.callback(config, params)
    end
  end
end
