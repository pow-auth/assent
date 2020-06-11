defmodule Assent.Strategy.DigitaloceanTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Digitalocean

  # From https://developers.digitalocean.com/documentation/v2/#account
  @user_response %{
    "account" => %{
      "droplet_limit" => 25,
      "floating_ip_limit" => 5,
      "volume_limit" => 10,
      "email" => "sammy@digitalocean.com",
      "uuid" => "b6fr89dbf6d9156cace5f3c78dc9851d957381ef",
      "email_verified" => true,
      "status" => "active",
      "status_message" => ""
    }
  }

  @user %{
    "email" => "sammy@digitalocean.com",
    "email_verified" => true,
    "sub" => "b6fr89dbf6d9156cace5f3c78dc9851d957381ef"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Digitalocean.authorize_url(config)
    assert url =~ "/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    config = Keyword.put(config, :user_url, "http://localhost:#{bypass.port}/v2/account")

    expect_oauth2_access_token_request(bypass, [uri: "/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)

    expect_oauth2_user_request(bypass, @user_response, uri: "/v2/account")

    assert {:ok, %{user: user}} = Digitalocean.callback(config, params)
    assert user == @user
  end
end
