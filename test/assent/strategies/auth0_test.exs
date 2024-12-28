defmodule Assent.Strategy.Auth0Test do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Auth0

  # From https://auth0.com/docs/get-started/apis/scopes/sample-use-cases-scopes-and-claims#authenticate-a-user-and-request-standard-claims
  @id_token_claims %{
    "name" => "John Doe",
    "nickname" => "john.doe",
    "picture" => "https://myawesomeavatar.com/avatar.png",
    "updated_at" => "2017-03-30T15:13:40.474Z",
    "email" => "john.doe@test.com",
    "email_verified" => false,
    "iss" => "https://{yourDomain}/",
    "sub" => "auth0|USER-ID",
    "aud" => "{yourClientId}",
    "exp" => :os.system_time(:second) + 60,
    "iat" => :os.system_time(:second),
    "nonce" => "crypto-value",
    "at_hash" => "IoS3ZGppJKUn3Bta_LgE2A"
  }
  @user %{
    "email" => "john.doe@test.com",
    "email_verified" => false,
    "sub" => "auth0|USER-ID",
    "name" => "John Doe",
    "nickname" => "john.doe",
    "picture" => "https://myawesomeavatar.com/avatar.png",
    "updated_at" => 1_490_886_820
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Auth0.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id=id"
    assert url =~ "scope=openid+email+profile"
  end

  test "callback/2", %{config: config, callback_params: params} do
    openid_config =
      config[:openid_configuration]
      |> Map.put("issuer", "https://{yourDomain}/")
      |> Map.put("token_endpoint_auth_methods_supported", ["client_secret_post"])

    session_params = Map.put(config[:session_params], :nonce, "crypto-value")

    config =
      Keyword.merge(config,
        openid_configuration: openid_config,
        client_id: "{yourClientId}",
        session_params: session_params
      )

    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: @id_token_claims, kid: key["kid"]])

    assert {:ok, %{user: user}} = Auth0.callback(config, params)
    assert user == @user
  end
end
