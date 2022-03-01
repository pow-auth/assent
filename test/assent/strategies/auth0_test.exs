defmodule Assent.Strategy.Auth0Test do
  use Assent.Test.OAuth2TestCase

  alias Assent.{Config.MissingKeyError, Strategy.Auth0}

  # From https://auth0.com/docs/api/authentication#user-profile
  @user_response %{
    "sub" => "248289761001",
    "name" => "Jane Josephine Doe",
    "given_name" => "Jane",
    "family_name" => "Doe",
    "middle_name" => "Josephine",
    "nickname" => "JJ",
    "preferred_username" => "j.doe",
    "profile" => "http://exampleco.com/janedoe",
    "picture" => "http://exampleco.com/janedoe/me.jpg",
    "website" => "http://exampleco.com",
    "email" => "janedoe@exampleco.com",
    "email_verified" => true,
    "gender" => "female",
    "birthdate" => "1972-03-31",
    "zoneinfo" => "America/Los_Angeles",
    "locale" => "en-US",
    "phone_number" => "+1 (111) 222-3434",
    "phone_number_verified" => false,
    "address" => %{
      "country" => "us"
    },
    "updated_at" => "1556845729"
  }
  @user @user_response

  describe "authorize_url/2" do
    test "requires domain or site configuration", %{config: config} do
      config = Keyword.take(config, [:client_id, :redirect_uri])

      assert Auth0.authorize_url(config) == {:error, %MissingKeyError{message: "Key `:site` not found in config"}}

      assert {:ok, %{url: url}} = Auth0.authorize_url(config ++ [site: "https://localhost"])
      assert url =~ "https://localhost/authorize"

      assert {:ok, %{url: url}} = Auth0.authorize_url(config ++ [domain: "demo.auth0.com"])
      assert url =~ "https://demo.auth0.com/authorize"

      assert {:ok, %{url: url}} = Auth0.authorize_url(config ++ [domain: "http://demo.auth0.com"])
      assert url =~ "http://demo.auth0.com/authorize"
    end
  end

  test "callback/2", %{config: config, callback_params: params} do
    expect_oauth2_access_token_request([uri: "/oauth/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)
    expect_oauth2_user_request(@user_response, uri: "/userinfo")

    assert {:ok, %{user: user}} = Auth0.callback(config, params)
    assert user == @user
  end
end
