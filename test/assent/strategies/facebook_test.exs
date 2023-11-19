defmodule Assent.Strategy.FacebookTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Facebook

  # From https://developers.facebook.com/tools/explorer/?method=GET&path=me%3Ffields%3Demail%2Cfirst_name%2Clast_name%2Cmiddle_name%2Cpicture%2Cgender%2Clink%2Cname%2Cname_format%2Cbirthday%2Cshort_name%2Cdomains%2Cwebsite&version=v4.0
  @user_response %{
    "name" => "Dan Schultzer",
    "first_name" => "Dan",
    "last_name" => "Schultzer",
    "email" => "foo@example.com",
    "id" => "1000001"
  }
  @user %{
    "email" => "foo@example.com",
    "family_name" => "Schultzer",
    "given_name" => "Dan",
    "name" => "Dan Schultzer",
    "sub" => "1000001"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Facebook.authorize_url(config)
    assert url =~ "https://www.facebook.com/v4.0/dialog/oauth?client_id="
  end

  describe "callback/2" do
    test "normalizes data", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request([uri: "/oauth/access_token"], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)

      expect_oauth2_user_request(@user_response, [uri: "/me"], fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)

        assert conn.params["access_token"] == "access_token"
        assert conn.params["fields"] == "email,name,first_name,last_name,middle_name,link"

        assert conn.params["appsecret_proof"] ==
                 Base.encode16(:crypto.mac(:hmac, :sha256, "secret", "access_token"),
                   case: :lower
                 )
      end)

      assert {:ok, %{user: user}} = Facebook.callback(config, params)
      assert user == Map.put(@user, "picture", TestServer.url("/1000001/picture"))
    end
  end
end
