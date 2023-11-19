defmodule Assent.Strategy.DiscordTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Discord

  # From https://discordapp.com/developers/docs/resources/user#user-object-example-user
  @user_response %{
    "id" => "80351110224678912",
    "username" => "Nelly",
    "discriminator" => "1337",
    "avatar" => "8342729096ea3675442027381ff50dfe",
    "verified" => true,
    "email" => "nelly@discordapp.com",
    "flags" => 64,
    "premium_type" => 1
  }
  @user %{
    "email" => "nelly@discordapp.com",
    "email_verified" => true,
    "picture" =>
      "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe",
    "preferred_username" => "Nelly",
    "sub" => "80351110224678912"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Discord.authorize_url(config)
    assert url =~ "/oauth2/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params} do
    expect_oauth2_access_token_request([uri: "/oauth2/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)

    expect_oauth2_user_request(@user_response, uri: "/users/@me")

    assert {:ok, %{user: user}} = Discord.callback(config, params)
    assert user == @user
  end
end
