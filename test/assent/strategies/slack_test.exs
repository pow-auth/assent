defmodule Assent.Strategy.SlackTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Slack

  @user_response %{
    "ok" => true,
    "user" => %{
      "name" => "Sonny Whether",
      "id" => "U0G9QF9C6",
      "email" => "sonny@captain-fabian.com",
      "image_24" => "https://secure.gravatar.com/avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg?s=24&d=https%3A%2F%2Fdev.slack.com%2Fimg%2Favatars%2Fava_0010-24.v1441146555.png",
      "image_32" => "https://secure.gravatar.com/avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg?s=32&d=https%3A%2F%2Fdev.slack.com%2Fimg%2Favatars%2Fava_0010-32.v1441146555.png",
      "image_48" => "https://secure.gravatar.com/avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg?s=48&d=https%3A%2F%2Fdev.slack.com%2Fimg%2Favatars%2Fava_0010-48.v1441146555.png",
      "image_72" => "https://secure.gravatar.com/avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg?s=72&d=https%3A%2F%2Fdev.slack.com%2Fimg%2Favatars%2Fava_0010-72.v1441146555.png",
      "image_192" => "https://secure.gravatar.com/avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg?s=192&d=https%3A%2F%2Fdev.slack.com%2Fimg%2Favatars%2Fava_0010-192.v1443724322.png",
      "image_512" => "https://secure.gravatar.com/avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg?s=512&d=https%3A%2F%2Fdev.slack.com%2Fimg%2Favatars%2Fava_0010-512.v1443724322.png"
    },
    "team" => %{
      "id" => "T0G9PQBBK",
      "name" => "Captain Fabian's Naval Supply"
    }
  }
  @user %{
    "uid" => "U0G9QF9C6-T0G9PQBBK",
    "image" => "https://secure.gravatar.com/avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg?s=48&d=https%3A%2F%2Fdev.slack.com%2Fimg%2Favatars%2Fava_0010-48.v1441146555.png",
    "name" => "Sonny Whether",
    "team_name" => "Captain Fabian's Naval Supply",
    "email" => "sonny@captain-fabian.com"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Slack.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    expect_oauth2_access_token_request(bypass, uri: "/api/oauth.access")
    expect_oauth2_user_request(bypass, @user_response, uri: "/api/users.identity")

    assert {:ok, %{user: user}} = Slack.callback(config, params)
    assert user == @user
  end
end
