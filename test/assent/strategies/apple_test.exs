defmodule Assent.Strategy.AppleTest do
  use Assent.Test.OIDCTestCase

  alias Assent.JWTAdapter.AssentJWT
  alias Assent.Strategy.Apple

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
  @id_token elem(Assent.Strategy.sign_jwt(
    %{
      "iss" => "https://appleid.apple.com",
      "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039",
      "aud" => @client_id,
      "exp" => :os.system_time(:second) + 5 * 60,
      "iat" => :os.system_time(:second),
      "email" => "john.doe@example.com"
    },
    "RS256",
    """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
    kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
    m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
    NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
    3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
    QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
    kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
    amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
    +bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
    D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
    0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
    lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
    hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
    bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
    +jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
    BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
    2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
    QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
    5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
    Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
    NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
    8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
    3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
    y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
    jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
    -----END RSA PRIVATE KEY-----
    """,
    []), 1)
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
    test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, [id_token: @id_token, uri: "/auth/token"], fn _conn, params ->
        assert {:ok, jwt} = AssentJWT.verify(params["client_secret"], @public_key, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["alg"] == "ES256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == @private_key_id
        assert jwt.claims["iss"] == @team_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == "http://localhost:#{bypass.port}"
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oidc_jwks_uri_request(bypass, uri: "/auth/keys", keys: [@jwk])

      assert {:ok, %{user: user}} = Apple.callback(config, params)
      assert user == @user
    end

    test "callback/2 with name scope", %{config: config, callback_params: params, bypass: bypass} do
      expected_user = Map.merge(@user, %{"given_name" => "John", "family_name" => "Doe"})

      opts = [
        params: %{
          access_token: "access_token",
          id_token: @id_token,
          user: %{
            email: "john.doe2@example.com",
            name: %{
              firstName: "John",
              lastName: "Doe"
            }
          }
        },
        uri: "/auth/token"]

      expect_oidc_access_token_request(bypass, opts)
      expect_oidc_jwks_uri_request(bypass, uri: "/auth/keys", keys: [@jwk])

      assert {:ok, %{user: user}} = Apple.callback(config, params)
      assert user == expected_user
    end
  else
    IO.warn("No support curve algorithms, can't test #{__MODULE__}")
  end
end
