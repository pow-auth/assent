defmodule Assent.Strategy.VKTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.VK

  # From https://vk.com/dev/first_guide
  @users_response [
    %{
      "id" => 210_700_286,
      "first_name" => "Lindsay",
      "last_name" => "Stirling"
    }
  ]
  @token_response %{
    "access_token" => "access_token",
    "id" => 66_748,
    "email" => "lindsay.stirling@example.com"
  }
  @user %{
    "given_name" => "Lindsay",
    "family_name" => "Stirling",
    "sub" => 210_700_286,
    "email" => "lindsay.stirling@example.com"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = VK.authorize_url(config)
    assert url =~ "/authorize"
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :token_url, TestServer.url("/access_token"))

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(uri: "/access_token", params: @token_response)

      expect_oauth2_user_request(%{"response" => @users_response}, [uri: "/method/users.get"], fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)

        assert conn.params["access_token"] == "access_token"
        assert conn.params["fields"] == "uid,first_name,last_name,photo_200,screen_name"
        assert conn.params["v"] == "5.69"
        assert conn.params["access_token"] == "access_token"
      end)

      assert {:ok, %{user: user}} = VK.callback(config, params)
      assert user == @user
    end

    test "handles invalid user response", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(uri: "/access_token", params: @token_response)
      expect_oauth2_user_request(%{"a" => 1}, [uri: "/method/users.get"])

      assert {:error, %RuntimeError{} = error} = VK.callback(config, params)
      assert error.message =~ "Retrieved an invalid response fetching VK user"
      assert error.message =~ "%{\"a\" => 1}"
    end
  end
end
