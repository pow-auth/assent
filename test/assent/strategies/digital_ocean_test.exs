defmodule Assent.Strategy.DigitalOceanTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.{Strategy.DigitalOcean, TestServer}

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
    assert {:ok, %{url: url}} = DigitalOcean.authorize_url(config)
    assert url =~ "https://cloud.digitalocean.com/v1/oauth/authorize?client_id="
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :token_url, TestServer.url("/v1/oauth/token"))

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request([uri: "/v1/oauth/token"], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)

      expect_oauth2_user_request(@user_response, uri: "/v2/account")

      assert {:ok, %{user: user}} = DigitalOcean.callback(config, params)
      assert user == @user
    end
  end
end
