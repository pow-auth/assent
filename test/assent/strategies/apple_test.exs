defmodule Assent.Strategy.AppleTest do
  use Assent.Test.OIDCTestCase

  alias Assent.JWTAdapter.AssentJWT
  alias Assent.{Strategy.Apple, TestServer}

  @client_id "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039"
  @team_id "app.test.client"
  @private_key_id "key_id"
  @private_key """
  -----BEGIN PRIVATE KEY-----
  MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
  OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
  1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
  -----END PRIVATE KEY-----
  """
  @public_key """
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
  q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
  -----END PUBLIC KEY-----
  """
  # Based on https://developer.apple.com/documentation/signinwithapplerestapi/authenticating_users_with_sign_in_with_apple
  @id_token_claims %{
    "iss" => "https://appleid.apple.com",
    "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039",
    "aud" => @client_id,
    "exp" => :os.system_time(:second) + 5 * 60,
    "iat" => :os.system_time(:second),
    "email" => "john.doe@example.com"
  }
  @user %{
    "email" => "john.doe@example.com",
    "email_verified" => true,
    "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039"
  }
  @jwk %{
    "kty" => "RSA",
    "kid" => "AIDOPK1",
    "use" => "sig",
    "alg" => "RS256",
    "n" => "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw",
    "e" => "AQAB"
  }

  setup %{config: config} do
    config =
      config
      |> Keyword.delete(:openid_configuration)
      |> Keyword.merge([
        client_id: @client_id,
        team_id: @team_id,
        private_key_id: @private_key_id,
        private_key: @private_key
      ])

    {:ok, config: config}
  end

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Apple.authorize_url(config)
    assert url =~ "/auth/authorize"
    assert url =~ "response_mode=form_post"
    assert url =~ "scope=email"
  end

  if :crypto.supports()[:curves] do
    test "callback/2", %{config: config, callback_params: params} do
      expect_oidc_access_token_request([id_token_opts: [claims: @id_token_claims], uri: "/auth/token"], fn _conn, params ->
        assert {:ok, jwt} = AssentJWT.verify(params["client_secret"], @public_key, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["alg"] == "ES256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == @private_key_id
        assert jwt.claims["iss"] == @team_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == TestServer.url()
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oidc_jwks_uri_request(uri: "/auth/keys", keys: [@jwk])

      assert {:ok, %{user: user}} = Apple.callback(config, params)
      assert user == @user
    end

    test "callback/2 with name scope", %{config: config, callback_params: params} do
      expected_user = Map.merge(@user, %{"given_name" => "John", "family_name" => "Doe"})

      encoded_user =
        Jason.encode!(%{name: %{
          firstName: "John",
          lastName: "Doe"
        }})

      params = Map.put(params, "user", encoded_user)

      expect_oidc_access_token_request(id_token_opts: [claims: @id_token_claims, kid: @jwk["kid"]], uri: "/auth/token")
      expect_oidc_jwks_uri_request(uri: "/auth/keys", keys: [@jwk])

      assert {:ok, %{user: user}} = Apple.callback(config, params)
      assert user == expected_user
    end
  else
    IO.warn("No support curve algorithms, can't test #{__MODULE__}")
  end
end
