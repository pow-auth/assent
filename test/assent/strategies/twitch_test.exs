defmodule Assent.Strategy.TwitchTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Twitch

  # From https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/#oidc-authorization-code-grant-flow
  @id_token_claims %{
    "iss" => "https://id.twitch.tv/oauth2",
    "sub" => "713936733",
    "aud" => "hof5gwx0su6owfnys0nyan9c87zr6t",
    "exp" => :os.system_time(:second) + 60,
    "iat" => :os.system_time(:second),
    "email" => "scotwht@justin.tv",
    "email_verified" => true,
    "picture" => "https://justin.tv/picture.png",
    "preferred_username" => "scotwht"
  }
  @user %{
    "email" => "scotwht@justin.tv",
    "email_verified" => true,
    "sub" => "713936733",
    "picture" => "https://justin.tv/picture.png",
    "preferred_username" => "scotwht"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Twitch.authorize_url(config)

    url = URI.parse(url)

    assert url.path == "/oauth/authorize"

    assert %{"client_id" => "id", "scope" => scope, "claims" => claims} =
             URI.decode_query(url.query)

    assert scope =~ "user:read:email"

    assert @json_library.decode!(claims)["id_token"] == %{
             "email" => nil,
             "email_verified" => nil,
             "picture" => nil,
             "preferred_username" => nil
           }
  end

  test "callback/2", %{config: config, callback_params: params} do
    openid_config =
      Map.put(config[:openid_configuration], "issuer", "https://id.twitch.tv/oauth2")

    config =
      Keyword.merge(config,
        openid_configuration: openid_config,
        client_id: "hof5gwx0su6owfnys0nyan9c87zr6t"
      )

    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: @id_token_claims, kid: key["kid"]])

    assert {:ok, %{user: user}} = Twitch.callback(config, params)
    assert user == @user
  end
end
