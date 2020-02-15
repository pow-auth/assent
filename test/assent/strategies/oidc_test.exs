defmodule Assent.Strategy.OIDCTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.OIDC

  describe "authorize_url/2" do
    test "generates url and state", %{config: config, bypass: bypass} do
      assert {:ok, %{url: url, session_params: %{state: state}}} = OIDC.authorize_url(config)

      refute is_nil(state)
      assert url =~ "http://localhost:#{bypass.port}/oauth/authorize?client_id=id&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&scope=openid&state=#{state}"
    end

    test "can add nonce", %{config: config, bypass: bypass} do
      assert {:ok, %{url: url, session_params: %{state: state, nonce: nonce}}} =
        config
        |> Keyword.put(:nonce, "n-0S6_WzA2Mj")
        |> OIDC.authorize_url()

      assert nonce == "n-0S6_WzA2Mj"
      assert url =~ "http://localhost:#{bypass.port}/oauth/authorize?client_id=id&nonce=n-0S6_WzA2Mj&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&scope=openid&state=#{state}"
    end
  end

  describe "authorize_url/2 with dynamic OpenID configuration" do
    setup %{config: config, bypass: bypass} do
      config = Keyword.delete(config, :openid_configuration)

      openid_config = %{
          "authorization_endpoint" => "http://localhost:#{bypass.port}/oauth/authorize"
        }

      {:ok, config: config, openid_config: openid_config}
    end

    test "pulls dynamic configuration", %{config: config, openid_config: openid_config, bypass: bypass} do
      expect_openid_config_request(bypass, openid_config)

      assert {:ok, %{url: url, session_params: %{state: state}}} = OIDC.authorize_url(config)

      refute is_nil(state)
      assert url =~ "http://localhost:#{bypass.port}/oauth/authorize?client_id=id&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&scope=openid&state=#{state}"
    end
  end

  describe "callback/2" do
    @user_claims %{sub: "1", name: "Dan Schultzer", email: "foo@example.com", email_verified: true}
    @user %{"email" => "foo@example.com", "name" => "Dan Schultzer", "sub" => "1", "email_verified" => true}
    @private_rsa_key """
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
      """
    @public_rsa_key """
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
      vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
      aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
      tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
      e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
      V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
      MwIDAQAB
      -----END PUBLIC KEY-----
      """

    test "with invalid id token", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, id_token: "invalid")

      assert OIDC.callback(config, params) == {:error, "The ID Token is not a valid JWT"}
    end

    test "with invalid `issuer` in id_token", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, id_token_claims: %{"iss" => "invalid"})

      assert OIDC.callback(config, params) == {:error, "Invalid issuer \"invalid\" in ID Token"}
    end

    test "with invalid `alg`", %{config: config, callback_params: params, bypass: bypass} do
      openid_configuration = Map.delete(config[:openid_configuration], "id_token_signed_response_alg")
      config               = Keyword.put(config, :openid_configuration, openid_configuration)

      expect_oidc_access_token_request(bypass, jwt_algorithm: "HS512")

      assert OIDC.callback(config, params) == {:error, "`alg` in ID Token can only be \"RS256\""}
    end

    test "with invalid `aud` in id_token", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, id_token_claims: %{"aud" => "invalid"})

      assert OIDC.callback(config, params) == {:error, "Invalid audience \"invalid\" in ID Token"}
    end

    test "with invalid signature in id_token", %{config: config, callback_params: params, bypass: bypass} do
      [header, payload, _signature] =
        bypass
        |> gen_id_token()
        |> String.split(".")

      expect_oidc_access_token_request(bypass, id_token: "#{header}.#{payload}.invalid")

      assert OIDC.callback(config, params) == {:error, "Invalid JWT signature for ID Token"}
    end

    test "with expired id_token", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, id_token_claims: %{"exp" => :os.system_time(:second)})

      assert OIDC.callback(config, params) == {:error, "The ID Token has expired"}
    end

    test "with TTL reached for id_token", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :id_token_ttl_seconds, 60)

      expect_oidc_access_token_request(bypass, id_token_claims: %{"iat" => :os.system_time(:second) - 60})

      assert OIDC.callback(config, params) == {:error, "The ID Token was issued too long ago"}
    end

    test "with missing nonce in id_token", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "n-0S6_WzA2Mj"))

      expect_oidc_access_token_request(bypass)

      assert OIDC.callback(config, params) == {:error, "`nonce` is not included in ID Token"}
    end

    test "with unexpected nonce in id_token", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, id_token_claims: %{"nonce" => "n-0S6_WzA2Mj"})

      assert OIDC.callback(config, params) == {:error, "`nonce` included in ID Token but doesn't exist in session params"}
    end

    test "with invalid nonce in id_token", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "n-0S6_WzA2Mj"))

      expect_oidc_access_token_request(bypass, id_token_claims: %{"nonce" => "invalid"})

      assert OIDC.callback(config, params) == {:error, "Invalid `nonce` included in ID Token"}
    end

    test "with valid nonce in id_token", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "n-0S6_WzA2Mj"))

      expect_oidc_access_token_request(bypass, id_token_claims: %{"nonce" => "n-0S6_WzA2Mj"})

      expect_oauth2_user_request(bypass, @user_claims)

      assert {:ok, _} = OIDC.callback(config, params)
    end

    test "with client_secret_basic authentication method", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, [], fn conn, _params ->
        assert [{"authorization", "Basic " <> token} | _rest] = conn.req_headers
        assert [client_id, client_secret] = String.split(Base.url_decode64!(token, padding: false), ":")

        assert client_id == config[:client_id]
        assert client_secret == config[:client_secret]
      end)

      expect_oauth2_user_request(bypass, @user_claims)

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == @user
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end

    test "with private_key_jwt authentication method", %{config: config, callback_params: params, bypass: bypass} do
      openid_configuration =
        config[:openid_configuration]
        |> Map.put("client_authentication_method", "private_key_jwt")
        |> Map.put("token_endpoint_auth_methods_supported", ["private_key_jwt"])

      config =
        config
        |> Keyword.put(:client_authentication_method, "private_key_jwt")
        |> Keyword.put(:openid_configuration, openid_configuration)
        |> Keyword.put(:private_key, @private_rsa_key)
        |> Keyword.put(:private_key_id, "key_id")

      expect_oidc_access_token_request(bypass, [], fn _conn, params ->
        assert {:ok, jwt} = Assent.JWTAdapter.AssentJWT.verify(params["client_assertion"], @public_rsa_key, json_library: Jason)
        assert jwt.header["alg"] == "RS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == "key_id"
        assert jwt.claims["iss"] == "id"
        assert jwt.claims["sub"] == "id"
        assert jwt.claims["aud"] == "http://localhost:#{bypass.port}"
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oauth2_user_request(bypass, @user_claims)

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == @user
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end
  end

  describe "callback/2 with dynamic OpenID configuration" do
    setup %{config: config} do
      config = Keyword.delete(config, :openid_configuration)

      openid_config = %{
        "token_endpoint" => "/dynamic/token/path",
        "issuer" => config[:site],
        "id_token_signed_response_alg" => ["HS256"]
      }

      {:ok, config: config, openid_config: openid_config}
    end

    test "pulls dynamic configuration", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, openid_config)

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path")

      assert {:ok, %{user: user}} = OIDC.callback(config, params)
      assert user == %{"sub" => "248289761001"}
    end

    test "with missing `token_endpoint` configuration options", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.delete(openid_config, "token_endpoint"))

      assert OIDC.callback(config, params) == {:error, "`token_endpoint` not found in OpenID configuration"}
    end

    test "with missing `issuer` configuration options", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.delete(openid_config, "issuer"))

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path")

      assert OIDC.callback(config, params) == {:error, "`issuer` not found in OpenID configuration"}
    end

    test "with invalid `alg` in id_token", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.put(openid_config, "id_token_signed_response_alg", ["custom"]))

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path")

      assert OIDC.callback(config, params) == {:error, "Unsupported algorithm \"HS256\" in ID Token"}
    end

    test "with missing `jwks_uri` configuration options", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, openid_config)

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", jwt_algorithm: "RS256")

      assert OIDC.callback(config, params) == {:error, "`jwks_uri` not found in OpenID configuration"}
    end

    test "with 404 `jwks_uri` url", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.put(openid_config, "jwks_uri", "http://localhost:#{bypass.port}/jwks_uri.json"))

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", jwt_algorithm: "RS256")

      Bypass.expect_once(bypass, "GET", "/jwks_uri.json", fn conn ->
        Plug.Conn.send_resp(conn, 404, "")
      end)

      assert {:error, %Assent.RequestError{error: :invalid_server_response}} = OIDC.callback(config, params)
    end

    test "with missing keys in `jwks_uri` url", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.put(openid_config, "jwks_uri", "http://localhost:#{bypass.port}/jwks_uri.json"))

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", jwt_algorithm: "RS256")

      Bypass.expect_once(bypass, "GET", "/jwks_uri.json", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, "{}")
      end)

      assert OIDC.callback(config, params) == {:error, "No keys found in `jwks_uri` provider configuration"}
    end

    test "with no `kid` in header and multiple keys fetched from `jwks_uri` url", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.put(openid_config, "jwks_uri", "http://localhost:#{bypass.port}/jwks_uri.json"))

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", jwt_algorithm: "RS256")

      expect_oidc_jwks_uri_request(bypass)

      assert OIDC.callback(config, params) == {:error, "Multiple public keys found in provider configuration and no `kid` value in ID Token"}
    end

    test "with no `kid` in header and single key fetched from `jwks_uri` url", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      openid_config =
        openid_config
        |> Map.put("id_token_signed_response_alg", ["RS256"])
        |> Map.put("jwks_uri", "http://localhost:#{bypass.port}/jwks_uri.json")

      expect_openid_config_request(bypass, openid_config)

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", jwt_algorithm: "RS256")

      expect_oidc_jwks_uri_request(bypass, count: 1)

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == %{"sub" => "248289761001"}
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end

    test "with no matching `kid` in keys fetched from `jwks_uri` url", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.put(openid_config, "jwks_uri", "http://localhost:#{bypass.port}/jwks_uri.json"))

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", jwt_algorithm: "RS256", jwt_kid: "invalid")

      expect_oidc_jwks_uri_request(bypass)

      assert OIDC.callback(config, params) == {:error, "No keys found for the `kid` value \"invalid\" provided in ID Token"}
    end

    test "with matching `kid` in keys fetched from `jwks_uri` url", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      openid_config =
        openid_config
        |> Map.put("id_token_signed_response_alg", ["RS256"])
        |> Map.put("jwks_uri", "http://localhost:#{bypass.port}/jwks_uri.json")

      expect_openid_config_request(bypass, openid_config)

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", jwt_algorithm: "RS256", jwt_kid: "key-1")

      expect_oidc_jwks_uri_request(bypass)

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == %{"sub" => "248289761001"}
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end

    test "with `userinfo_endpoint` in configuration options", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, Map.put(openid_config, "userinfo_endpoint", "/dynamic/userinfo/path"))

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path")

      expect_oauth2_user_request(bypass, @user_claims, uri: "/dynamic/userinfo/path")

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == @user
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end
  end
end
