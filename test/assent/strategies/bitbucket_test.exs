defmodule Assent.Strategy.BitbucketTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Bitbucket

  @user_response %{
    "account_id" => "8675309:1bf26c46-c29b-4fc0-bda2-e5c5f1adde19",
    "account_status" => "active",
    "created_on" => "2023-03-17T03:27:21.528051+00:00",
    "display_name" => "Johnny O",
    "has_2fa_enabled" => nil,
    "is_staff" => false,
    "links" => %{
      "avatar" => %{
        "href" =>
          "https://i1.wp.com/avatar-management--avatars.us-west-2.prod.public.atl-paas.net/initials.png?ssl=1"
      },
      "hooks" => %{
        "href" =>
          "https://api.bitbucket.org/2.0/workspaces/%7B1bf26c46-c29b-4fc0-bda2-e5c5f1adde19%7D/hooks"
      },
      "html" => %{
        "href" => "https://bitbucket.org/%7B1bf26c46-c29b-4fc0-bda2-e5c5f1adde19%7D/"
      },
      "repositories" => %{
        "href" =>
          "https://api.bitbucket.org/2.0/repositories/%7B1bf26c46-c29b-4fc0-bda2-e5c5f1adde19%7D"
      },
      "self" => %{
        "href" => "https://api.bitbucket.org/2.0/users/%7B1bf26c46-c29b-4fc0-bda2-e5c5f1adde19%7D"
      },
      "snippets" => %{
        "href" =>
          "https://api.bitbucket.org/2.0/snippets/%7B1bf26c46-c29b-4fc0-bda2-e5c5f1adde19%7D"
      }
    },
    "location" => nil,
    "nickname" => "Johnny",
    "type" => "user",
    "username" => "djgoku",
    "uuid" => "{1bf26c46-c29b-4fc0-bda2-e5c5f1adde19}"
  }
  @emails_response %{
    "page" => 1,
    "pagelen" => 10,
    "size" => 1,
    "values" => [
      %{
        "email" => "test@localhost",
        "is_confirmed" => true,
        "is_primary" => true,
        "links" => %{
          "self" => %{
            "href" => "https://api.bitbucket.org/2.0/user/emails/test@localhost"
          }
        },
        "type" => "email"
      }
    ]
  }
  @user %{
    "email" => "test@localhost",
    "email_verified" => true,
    "name" => "Johnny O",
    "nickname" => "Johnny",
    "picture" =>
      "https://i1.wp.com/avatar-management--avatars.us-west-2.prod.public.atl-paas.net/initials.png?ssl=1",
    "preferred_username" => "djgoku",
    "sub" => "8675309:1bf26c46-c29b-4fc0-bda2-e5c5f1adde19"
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

      expect_oauth2_user_request(@user_response, uri: "/user")
      expect_oauth2_api_request("/user/emails", @emails_response)

      assert {:ok, %{user: user}} = Bitbucket.callback(config, params)
      assert user == @user
    end
  end
end
