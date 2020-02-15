defmodule Assent.Strategy.GithubTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Github

  # From https://developer.github.com/v3/users/
  @user_response %{
    "login" => "octocat",
    "id" => 1,
    "node_id" => "MDQ6VXNlcjE=",
    "avatar_url" => "https://github.com/images/error/octocat_happy.gif",
    "gravatar_id" => "",
    "url" => "https://api.github.com/users/octocat",
    "html_url" => "https://github.com/octocat",
    "followers_url" => "https://api.github.com/users/octocat/followers",
    "following_url" => "https://api.github.com/users/octocat/following{/other_user}",
    "gists_url" => "https://api.github.com/users/octocat/gists{/gist_id}",
    "starred_url" => "https://api.github.com/users/octocat/starred{/owner}{/repo}",
    "subscriptions_url" => "https://api.github.com/users/octocat/subscriptions",
    "organizations_url" => "https://api.github.com/users/octocat/orgs",
    "repos_url" => "https://api.github.com/users/octocat/repos",
    "events_url" => "https://api.github.com/users/octocat/events{/privacy}",
    "received_events_url" => "https://api.github.com/users/octocat/received_events",
    "type" => "User",
    "site_admin" => false,
    "name" => "monalisa octocat",
    "company" => "GitHub",
    "blog" => "https://github.com/blog",
    "location" => "San Francisco",
    "email" => "octocat@github.com",
    "hireable" => false,
    "bio" => "There once was...",
    "public_repos" => 2,
    "public_gists" => 1,
    "followers" => 20,
    "following" => 0,
    "created_at" => "2008-01-14T04:33:35Z",
    "updated_at" => "2008-01-14T04:33:35Z"
  }
  # From https://developer.github.com/v3/users/emails/
  @emails_response [
    %{
      "email" => "support@github.com",
      "verified" => false,
      "primary" => false,
      "visibility" => "public"
    },
    %{
      "email" => "octocat@github.com",
      "verified" => true,
      "primary" => true,
      "visibility" => "public"
    },
    %{
      "email" => "octocat@octocat.org",
      "verified" => true,
      "primary" => false,
      "visibility" => "public"
    }
  ]
  @user %{
    "email" => "octocat@github.com",
    "email_verified" => true,
    "name" => "monalisa octocat",
    "picture" => "https://github.com/images/error/octocat_happy.gif",
    "preferred_username" => "octocat",
    "profile" => "https://github.com/octocat",
    "sub" => 1
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Github.authorize_url(config)
    assert url =~ "https://github.com/login/oauth/authorize?client_id="
  end

  describe "callback/2" do
    setup %{config: config, bypass: bypass} do
      config = Keyword.put(config, :token_url, "http://localhost:#{bypass.port}/login/oauth/access_token")

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, [uri: "/login/oauth/access_token"], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)
      expect_oauth2_user_request(bypass, @user_response, uri: "/user")
      expect_oauth2_api_request(bypass, "/user/emails", @emails_response)

      assert {:ok, %{user: user}} = Github.callback(config, params)
      assert user == @user
    end
  end
end
