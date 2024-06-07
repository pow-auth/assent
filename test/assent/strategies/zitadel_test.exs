defmodule Assent.Strategy.ZitadelTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Zitadel

  @client_id "nameofproject@3425235252"
  @id_token_claims %{
    "iss" => "https://zitadel.cloud",
    "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039",
    "aud" => @client_id,
    "exp" => :os.system_time(:second) + 5 * 60,
    "iat" => :os.system_time(:second),
    "email" => "john.doe@example.com",
    "nonce" => "123523"
  }
  @user %{
    "email" => "john.doe@example.com",
    "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039"
  }

  setup %{config: config, callback_params: callback_params} do
    openid_config = %{
      "issuer" => "https://zitadel.cloud",
      "authorization_endpoint" => TestServer.url("/oauth/v2/authorize"),
      "token_endpoint" => TestServer.url("/oauth/v2/token"),
      "userinfo_endpoint" => TestServer.url("/userinfo"),
      "jwks_uri" => TestServer.url("/jwks_uri.json"),
      "token_endpoint_auth_methods_supported" => ["client_secret_post"]
    }

    openid_configuration =
      Map.merge(Map.delete(config[:openid_configuration], "issuer"), openid_config)

    config = Keyword.put(config, :openid_configuration, openid_configuration)

    callback_params =
      Map.merge(callback_params, %{"nonce" => "123523", "code_verifier" => "456856"})

    {:ok, config: config, callback_params: callback_params}
  end

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Zitadel.authorize_url(config)
    assert url =~ "/oauth/v2/authorize?client_id=id"
    assert url =~ "scope=openid+email"
    assert url =~ "response_type=code"
  end

  test "authorize_url/2 with PKCE", %{config: config} do
    assert {:ok, %{url: url}} = Zitadel.authorize_url(config ++ [code_verifier: true, nonce: true])
    assert url =~ "/oauth/v2/authorize?client_id=id"
    assert url =~ "scope=openid+email"
    assert url =~ "response_type=code"
    assert url =~ "code_challenge="
    assert url =~ "nonce="
    assert url =~ "state="
    assert url =~ "code_challenge_method=S256"
    assert not String.match?(url, ~r/code_verifier/)
  end

  test "callback/2", %{config: config, callback_params: params} do
    openid_config =
      config[:openid_configuration]
      |> Map.put(
        "issuer",
        "https://zitadel.cloud"
      )
      |> Map.put("token_endpoint_auth_methods_supported", [
        "client_secret_post",
        "private_key_jwt",
        "client_secret_basic"
      ])

    session_params = Map.put(config[:session_params], :nonce, "123523")
    session_params = Map.put(session_params, :code_verifier, "456856")

    config =
      Keyword.merge(config,
        openid_configuration: openid_config,
        client_id: @client_id,
        session_params: session_params
      )

    [key | _rest] = expect_oidc_jwks_uri_request()

    expect_oidc_access_token_request(
      id_token_opts: [claims: @id_token_claims, kid: key["kid"]],
      uri: "/oauth/v2/token"
    )

    assert {:ok, %{user: user}} = Zitadel.callback(config, params)
    assert user == @user
  end
end
