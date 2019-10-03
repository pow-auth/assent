defmodule Assent.Strategy.SlackTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Slack

  # From https://api.slack.com/methods/users.identity
  @user_response %{
    "ok" => true,
    "user" => %{
      "name" => "Sonny Whether",
      "id" => "U0G9QF9C6",
      "email" => "sonny@captain-fabian.com",
      "image_24" => "https://cdn.example.com/sonny_24.jpg",
      "image_32" => "https://cdn.example.com/sonny_32.jpg",
      "image_48" => "https://cdn.example.com/sonny_48.jpg",
      "image_72" => "https://cdn.example.com/sonny_72.jpg",
      "image_192" => "https://cdn.example.com/sonny_192.jpg"
    },
    "team" => %{
      "id" => "T0G9PQBBK",
      "name" => "Captain Fabian's Naval Supply"
    }
  }
  @user %{
    "email" => "sonny@captain-fabian.com",
    "name" => "Sonny Whether",
    "picture" => "https://cdn.example.com/sonny_48.jpg",
    "slack_team" => %{
      "id" => "T0G9PQBBK",
      "name" => "Captain Fabian's Naval Supply"
    },
    "sub" => "U0G9QF9C6-T0G9PQBBK"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Slack.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    expect_oauth2_access_token_request(bypass, [uri: "/api/oauth.access"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)
    expect_oauth2_user_request(bypass, @user_response, uri: "/api/users.identity")

    assert {:ok, %{user: user}} = Slack.callback(config, params)
    assert user == @user
  end
end
