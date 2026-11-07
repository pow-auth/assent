defmodule Assent.Strategy.OIDCTest do
  use Assent.Test.OIDCTestCase

  doctest Assent.Strategy.OIDC
  doctest Assent.Strategy.OIDC.InvalidIDTokenError
  doctest Assent.Strategy.OIDC.InvalidOpenIDConfigurationError
  doctest Assent.Strategy.OIDC.InvalidUserInfoError

  alias Assent.{JWTAdapter.AssentJWT, MissingConfigError, MissingParamError, Strategy.OIDC}

  alias Assent.HTTPAdapter.{
    InvalidResponseError,
    RequestError,
    ServerUnreachableError,
    UnexpectedResponseError
  }

  alias Assent.Strategy.OIDC.{
    InvalidIDTokenError,
    InvalidOpenIDConfigurationError,
    InvalidUserInfoError
  }

  describe "authorize_url/1" do
    test "with default config", %{config: config} do
      assert {:ok, %{url: url, session_params: %{state: state}}} = OIDC.authorize_url(config)

      refute is_nil(state)

      assert url =~
               TestServer.url(
                 "/oauth/authorize?client_id=id&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&scope=openid&state=#{state}"
               )
    end

    test "with `:nonce` config", %{config: config} do
      assert {:ok, %{url: url, session_params: %{state: state, nonce: nonce}}} =
               config
               |> Keyword.put(:nonce, "n-0S6_WzA2Mj")
               |> OIDC.authorize_url()

      assert nonce == "n-0S6_WzA2Mj"

      assert url =~
               TestServer.url(
                 "/oauth/authorize?client_id=id&nonce=n-0S6_WzA2Mj&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&scope=openid&state=#{state}"
               )
    end

    test "with `nonce: true` config", %{config: config} do
      assert {:ok, %{url: url, session_params: session_params}} =
               config
               |> Keyword.put(:nonce, true)
               |> OIDC.authorize_url()

      assert String.length(session_params.nonce) == 22

      query_params = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      assert query_params["nonce"] == session_params.nonce
    end
  end

  describe "callback/2 with static OpenID configuration" do
    test "with invalid authentication method", %{config: config, callback_params: params} do
      config = Keyword.put(config, :client_authentication_method, "invalid")

      assert {:error, %ArgumentError{} = error} = OIDC.callback(config, params)

      assert Exception.message(error) == "invalid client authentication method, got: \"invalid\""
    end

    test "with missing `token_endpoint` in OpenID configuration", %{
      config: config,
      callback_params: params
    } do
      openid_config =
        config
        |> Keyword.get(:openid_configuration)
        |> Map.delete("token_endpoint")

      config = Keyword.put(config, :openid_configuration, openid_config)

      assert {:error, %InvalidOpenIDConfigurationError{} = error} = OIDC.callback(config, params)

      assert Exception.message(error) ==
               "expected `token_endpoint` in OpenID Provider configuration"
    end

    test "with invalid ID Token", %{config: config, callback_params: params} do
      expect_oidc_access_token_request(id_token: "invalid")

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.callback(config, params)

      assert Exception.message(error) == "expected JWT to have three parts, got: 1"
    end

    @user_claims %{
      sub: "1",
      name: "Dan Schultzer",
      email: "foo@example.com",
      email_verified: true,
      "http://localhost:4000/additional": "info"
    }
    @user %{
      "email" => "foo@example.com",
      "name" => "Dan Schultzer",
      "sub" => "1",
      "email_verified" => true,
      "http://localhost:4000/additional" => "info"
    }

    test "with `client_authentication_method: \"none\"` config", %{
      config: config,
      callback_params: params
    } do
      expect_oidc_access_token_request(
        [id_token_opts: [claims: @user_claims, iss: "http://localhost"]],
        fn conn, params ->
          assert Plug.Conn.get_req_header(conn, "authorization") == []
          assert params["client_id"] == config[:client_id]
          refute params["client_secret"]
        end
      )

      expect_oidc_jwks_uri_request(count: 1)

      config = Keyword.put(config, :client_authentication_method, "none")

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == @user
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end

    test "with `client_authentication_method: \"client_secret_basic\"` config", %{
      config: config,
      callback_params: params
    } do
      expect_oidc_access_token_request(
        [id_token_opts: [claims: @user_claims, iss: "http://localhost"]],
        fn conn, _params ->
          assert ["Basic " <> token] = Plug.Conn.get_req_header(conn, "authorization")

          assert [client_id, client_secret] =
                   String.split(Base.url_decode64!(token, padding: false), ":")

          assert client_id == config[:client_id]
          assert client_secret == config[:client_secret]
        end
      )

      expect_oidc_jwks_uri_request(count: 1)

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == @user
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end

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

    test "with `client_authentication_method: \"private_key_jwt\"` config", %{
      config: config,
      callback_params: params
    } do
      openid_config =
        config
        |> Keyword.get(:openid_configuration)
        |> Map.put("token_endpoint", TestServer.url("/oidc/token"))

      config =
        config
        |> Keyword.put(:client_authentication_method, "private_key_jwt")
        |> Keyword.put(:private_key, @private_rsa_key)
        |> Keyword.put(:private_key_id, "key_id")
        |> Keyword.put(:openid_configuration, openid_config)

      token_url = TestServer.url("/oidc/token")

      expect_oidc_access_token_request(
        [
          uri: "/oidc/token",
          id_token_opts: [claims: @user_claims, iss: "http://localhost"]
        ],
        fn _conn, params ->
          assert {:ok, jwt} =
                   AssentJWT.verify(params["client_assertion"], @public_rsa_key,
                     json_library: Assent.json_library([])
                   )

          assert jwt.header["alg"] == "RS256"
          assert jwt.header["typ"] == "JWT"
          assert jwt.header["kid"] == "key_id"
          assert jwt.claims["iss"] == "id"
          assert jwt.claims["sub"] == "id"
          assert jwt.claims["aud"] == token_url
          assert String.length(jwt.claims["jti"]) == 32
          assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
        end
      )

      expect_oidc_jwks_uri_request(count: 1)

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
        "jwks_uri" => TestServer.url("/jwks_uri.json"),
        "issuer" => config[:base_url]
      }

      {:ok, config: config, openid_config: openid_config}
    end

    test "with unreachable OpenID configuration URL", %{config: config, callback_params: params} do
      openid_config_url = TestServer.url("/.well-known/openid-configuration")
      TestServer.stop()

      assert {:error, %ServerUnreachableError{} = error} = OIDC.callback(config, params)

      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request.url == openid_config_url
      assert {:failed_connect, _} = error.reason
    end

    test "with unexpected OpenID configuration URL response", %{
      config: config,
      openid_config: openid_config,
      callback_params: params
    } do
      expect_openid_config_request(openid_config, status_code: 201)

      assert {:error, %UnexpectedResponseError{}} = OIDC.callback(config, params)
    end

    test "with OpenID configuration URL returning 404", %{
      config: config,
      openid_config: openid_config,
      callback_params: params
    } do
      expect_openid_config_request(openid_config, status_code: 404)

      assert {:error, %InvalidResponseError{} = error} = OIDC.callback(config, params)

      assert error.response.status == 404
    end

    test "with missing `issuer` in OpenID configuration", %{
      config: config,
      openid_config: openid_config,
      callback_params: params
    } do
      expect_openid_config_request(Map.delete(openid_config, "issuer"))

      assert {:error, %InvalidOpenIDConfigurationError{} = error} = OIDC.callback(config, params)

      assert Exception.message(error) == "expected `issuer` in OpenID Provider configuration"
    end

    test "with different `issuer` in OpenID configuration", %{
      config: config,
      openid_config: openid_config,
      callback_params: params
    } do
      expect_openid_config_request(Map.put(openid_config, "issuer", "https://other.example.com"))

      assert {:error, %InvalidOpenIDConfigurationError{} = error} = OIDC.callback(config, params)

      assert Exception.message(error) ==
               "expected `issuer` to be #{inspect(config[:base_url])}, got: \"https://other.example.com\""
    end

    test "with invalid ID Token", %{
      config: config,
      openid_config: openid_config,
      callback_params: params
    } do
      expect_openid_config_request(openid_config)
      expect_oidc_access_token_request(uri: "/dynamic/token/path", id_token: "invalid")

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.callback(config, params)

      assert Exception.message(error) == "expected JWT to have three parts, got: 1"
    end

    test "with missing ID Token", %{
      config: config,
      openid_config: openid_config,
      callback_params: params
    } do
      expect_openid_config_request(openid_config)

      expect_oidc_access_token_request(
        uri: "/dynamic/token/path",
        params: %{access_token: "access_token", renewal_token: "renewal_token"}
      )

      assert {:error, %MissingParamError{} = error} = OIDC.callback(config, params)

      assert error.key == "id_token"
    end

    test "with valid ID Token", %{
      config: config,
      openid_config: openid_config,
      callback_params: params
    } do
      expect_openid_config_request(openid_config)
      expect_oidc_access_token_request(uri: "/dynamic/token/path")
      expect_oidc_jwks_uri_request(count: 1)

      assert {:ok, %{user: user}} = OIDC.callback(config, params)
      assert user == %{"sub" => "1"}
    end
  end

  describe "validate_id_token/2 with `alg=none`" do
    setup %{config: config} do
      id_token = gen_id_token(alg: "none")
      config = Keyword.put(config, :id_token_signed_response_alg, "none")

      {:ok, id_token: id_token, config: config}
    end

    test "with unsigned JWT", %{config: config, id_token: id_token} do
      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected JWT signature to be valid"
    end
  end

  describe "validate_id_token/2 with `alg=HS256`" do
    setup %{config: config} do
      id_token = gen_id_token(alg: "HS256")
      config = Keyword.put(config, :id_token_signed_response_alg, "HS256")

      {:ok, id_token: id_token, config: config}
    end

    test "with unavailable OpenID configuration", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :openid_configuration)

      expect_openid_config_request([], status_code: 500)

      assert {:error, %InvalidResponseError{}} = OIDC.validate_id_token(config, id_token)
    end

    test "with missing `:client_id` config", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :client_id)

      assert {:error, %MissingConfigError{} = error} = OIDC.validate_id_token(config, id_token)

      assert error.key == :client_id
    end

    test "with missing `issuer` in OpenID configuration", %{config: config, id_token: id_token} do
      openid_config = Map.delete(Keyword.get(config, :openid_configuration), "issuer")
      config = Keyword.put(config, :openid_configuration, openid_config)

      assert {:error, %InvalidOpenIDConfigurationError{} = error} =
               OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected `issuer` in OpenID Provider configuration"
    end

    test "with invalid JWT", %{config: config} do
      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, "invalid")

      assert Exception.message(error) == "expected JWT to have three parts, got: 1"
      assert is_nil(error.reason)
    end

    test "with invalid base64url-encoded header", %{config: config, id_token: id_token} do
      id_token = replace_jwt_header(id_token, "@invalid")

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected JWT header to be base64url-encoded"
      assert is_nil(error.reason)
    end

    test "with invalid JSON-encoded header", %{config: config, id_token: id_token} do
      header = Base.url_encode64("not-json", padding: false)
      id_token = replace_jwt_header(id_token, header)

      assert {:error, %InvalidIDTokenError{} = error} =
               OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "could not decode JWT header"
      assert error.reason == {:invalid_byte, 1, 111}
    end

    test "with non-object JSON-encoded header", %{config: config, id_token: id_token} do
      header = Base.url_encode64(JSON.encode!([]), padding: false)
      id_token = replace_jwt_header(id_token, header)

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected JWT header to be a JSON object"
      assert is_nil(error.reason)
    end

    test "with unexpected `alg` in header", %{config: config, id_token: id_token} do
      assert {:error, %InvalidIDTokenError{} = error} =
               OIDC.validate_id_token(
                 Keyword.delete(config, :id_token_signed_response_alg),
                 id_token
               )

      assert Exception.message(error) ==
               "expected `alg` in JWT header to be \"RS256\", got: \"HS256\""

      id_token = gen_id_token(alg: "none")

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `alg` in JWT header to be \"HS256\", got: \"none\""
    end

    test "with missing `alg` in header", %{config: config, id_token: id_token} do
      header = Base.url_encode64(JSON.encode!(%{}), padding: false)
      id_token = replace_jwt_header(id_token, header)

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected `alg` in JWT header, got: []"
    end

    test "with missing `:client_secret` config", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :client_secret)

      assert {:error, %MissingConfigError{} = error} = OIDC.validate_id_token(config, id_token)

      assert error.key == :client_secret
    end

    test "with invalid signature", %{config: config, id_token: id_token} do
      [header, payload, _signature] = String.split(id_token, ".")
      id_token = "#{header}.#{payload}.invalid"

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected JWT signature to be valid"
    end

    test "with JWT verification error", %{config: config, id_token: id_token} do
      config = Keyword.put(config, :id_token_signed_response_alg, "HS000")
      header = Base.url_encode64(JSON.encode!(%{"alg" => "HS000"}), padding: false)
      id_token = replace_jwt_header(id_token, header)

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "could not verify JWT"
      assert %AssentJWT.Error{} = error.reason
    end

    for key <- ~w(iss sub aud exp iat) do
      test "with missing `#{key}`", %{config: config} do
        id_token = gen_id_token(alg: "HS256", claims: %{unquote(key) => nil})
        expected_keys = ~w(aud exp iat iss sub) -- [unquote(key)]

        assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

        assert Exception.message(error) ==
                 "expected `#{unquote(key)}` in claims, got: #{inspect(expected_keys)}"
      end
    end

    test "with invalid `iss`", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"iss" => "invalid"})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `iss` in claims to be trusted, got: \"invalid\""
    end

    test "with `iss` not the issuer nor in `:trusted_issuers` config", %{config: config} do
      config = Keyword.put(config, :trusted_issuers, ["https://example.com"])
      id_token = gen_id_token(alg: "HS256", iss: "https://untrusted.com")

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `iss` in claims to be trusted, got: \"https://untrusted.com\""
    end

    test "with `iss` in `:trusted_issuers` config", %{config: config} do
      config = Keyword.put(config, :trusted_issuers, ["https://example.com"])
      id_token = gen_id_token(alg: "HS256", iss: "https://example.com")

      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)
      assert jwt.verified?
    end

    test "with invalid `aud`", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => "invalid"})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to include `:client_id`, got: [\"invalid\"]"
    end

    test "with `aud` case mismatch", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => "ID"})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to include `:client_id`, got: [\"ID\"]"
    end

    test "with `aud` list not containing `:client_id` config value", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(aud1 aud2)})
      config = Keyword.put(config, :trusted_audiences, ~w(aud1 aud2))

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to include `:client_id`, got: [\"aud1\", \"aud2\"]"
    end

    test "with `aud` list and missing `:trusted_audiences` config", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(id aud1 aud2)})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to contain only trusted audiences, got: [\"id\", \"aud1\", \"aud2\"]"
    end

    test "with `aud` list containing untrusted audiences", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(id aud1 aud2)})
      config = Keyword.put(config, :trusted_audiences, ~w(aud1))

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to contain only trusted audiences, got: [\"id\", \"aud1\", \"aud2\"]"
    end

    test "with `aud` list containing only `:client_id` config value", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(id)})

      assert {:ok, _} = OIDC.validate_id_token(config, id_token)
    end

    test "with `aud` list", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(id aud1 aud2)})
      config = Keyword.put(config, :trusted_audiences, ~w(aud1 aud2))

      assert {:ok, _} = OIDC.validate_id_token(config, id_token)
    end

    test "with invalid `azp`", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"azp" => "invalid"})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `azp` in claims to match `:client_id`, got: \"invalid\""
    end

    test "with valid `azp`", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"azp" => "id"})

      assert {:ok, _} = OIDC.validate_id_token(config, id_token)
    end

    test "with `exp` in the past", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"exp" => :os.system_time(:second)})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected `exp` in claims to be in the future"
    end

    test "with `iat` older than `:id_token_ttl_seconds` config value", %{config: config} do
      config = Keyword.put(config, :id_token_ttl_seconds, 60)
      id_token = gen_id_token(alg: "HS256", claims: %{"iat" => :os.system_time(:second) - 60})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected `iat` in claims to be no older than 60 seconds"
    end

    test "with missing `:session_params` config", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :session_params)

      assert {:error, %MissingConfigError{} = error} = OIDC.validate_id_token(config, id_token)

      assert error.key == :session_params
    end

    test "with `nonce` and missing `:nonce` in `:session_params` config", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"nonce" => "a"})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `:nonce` in session params because claims contain `nonce`"
    end

    test "with missing `nonce` and `:nonce` in `:session_params` config", %{
      config: config,
      id_token: id_token
    } do
      config =
        Keyword.put(
          config,
          :session_params,
          Map.put(config[:session_params], :nonce, "n-0S6_WzA2Mj")
        )

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `nonce` in claims, got: [\"aud\", \"exp\", \"iat\", \"iss\", \"sub\"]"
    end

    test "with `nonce` not matching `:nonce` in `:session_params` config", %{config: config} do
      config = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "b"))
      id_token = gen_id_token(alg: "HS256", claims: %{"nonce" => "a"})

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `nonce` in claims to match `:nonce` in session params"
    end

    test "with missing `nonce` and missing `:nonce` in `:session_params` config", %{
      config: config,
      id_token: id_token
    } do
      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)

      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end

    test "with valid `nonce`", %{config: config} do
      config = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "a"))
      id_token = gen_id_token(alg: "HS256", claims: %{"nonce" => "a"})

      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)
      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end
  end

  describe "validate_id_token/2 with `alg=RS256`" do
    setup %{config: config} do
      id_token = gen_id_token()

      {:ok, config: config, id_token: id_token}
    end

    test "with missing `jwks_uri` in OpenID configuration", %{config: config, id_token: id_token} do
      openid_config = Map.delete(Keyword.get(config, :openid_configuration), "jwks_uri")
      config = Keyword.put(config, :openid_configuration, openid_config)

      assert {:error, %InvalidOpenIDConfigurationError{} = error} =
               OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) == "expected `jwks_uri` in OpenID Provider configuration"
    end

    test "with unreachable `jwks_uri` URL", %{config: config, id_token: id_token} do
      jwks_uri_url = TestServer.url("/jwks_uri.json")
      TestServer.stop()

      assert {:error, %ServerUnreachableError{} = error} =
               OIDC.validate_id_token(config, id_token)

      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request.url == jwks_uri_url
      assert {:failed_connect, _} = error.reason
    end

    test "with unexpected `jwks_uri` URL response", %{config: config, id_token: id_token} do
      expect_oidc_jwks_uri_request(status_code: 201)

      assert {:error, %UnexpectedResponseError{} = error} =
               OIDC.validate_id_token(config, id_token)

      assert error.response.status == 201
    end

    test "with `jwks_uri` URL returning 404", %{config: config, id_token: id_token} do
      TestServer.add("/jwks_uri.json",
        via: :get,
        to: fn conn ->
          Plug.Conn.send_resp(conn, 404, "")
        end
      )

      assert {:error, %InvalidResponseError{} = error} = OIDC.validate_id_token(config, id_token)

      assert error.response.status == 404
    end

    test "with `jwks_uri` URL response missing `keys`", %{config: config, id_token: id_token} do
      TestServer.add("/jwks_uri.json",
        via: :get,
        to: fn conn ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, "{}")
        end
      )

      assert {:error, %InvalidOpenIDConfigurationError{} = error} =
               OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `jwks_uri` in OpenID Provider configuration to contain keys"
    end

    test "with `jwks_uri` URL response containing malformed key entries", %{config: config} do
      id_token = gen_id_token(kid: "invalid")

      expect_oidc_jwks_uri_request(keys: [nil])

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected provider key IDs to include \"invalid\", got: []"
    end

    test "with missing `kid` in header and multiple provider keys in `jwks_uri` URL response", %{
      config: config,
      id_token: id_token
    } do
      expect_oidc_jwks_uri_request()

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected `kid` in JWT header because provider returned multiple keys"
    end

    test "with `kid` in header not matching provider keys in `jwks_uri` URL response", %{
      config: config
    } do
      id_token = gen_id_token(kid: "invalid")

      expect_oidc_jwks_uri_request()

      assert {:error, %InvalidIDTokenError{} = error} = OIDC.validate_id_token(config, id_token)

      assert Exception.message(error) ==
               "expected provider key IDs to include \"invalid\", got: [\"key-1\", \"key-2\"]"
    end

    test "with missing `kid` in header and one provider key in `jwks_uri` URL response", %{
      config: config,
      id_token: id_token
    } do
      expect_oidc_jwks_uri_request(count: 1)

      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)

      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end

    test "with `kid` in header matching provider keys in `jwks_uri` URL response", %{
      config: config
    } do
      id_token = gen_id_token(kid: "key-1")

      expect_oidc_jwks_uri_request()

      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)

      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end
  end

  describe "fetch_userinfo/2" do
    setup %{config: config} do
      id_token = gen_id_token(alg: "HS256")

      config =
        config
        |> Keyword.put(:id_token_signed_response_alg, "HS256")
        |> Keyword.put(:userinfo_signed_response_alg, "HS256")

      access_token = %{"access_token" => "access_token", "id_token" => id_token}

      {:ok, config: config, access_token: access_token}
    end

    test "with unavailable OpenID configuration", %{config: config, access_token: access_token} do
      config = Keyword.delete(config, :openid_configuration)
      expect_openid_config_request([], status_code: 500)

      assert {:error, %InvalidResponseError{}} = OIDC.fetch_userinfo(config, access_token)
    end

    test "with missing `id_token` in access token", %{config: config, access_token: access_token} do
      access_token = Map.delete(access_token, "id_token")

      assert {:error, %MissingParamError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert error.key == "id_token"
    end

    test "with invalid `id_token` in access token", %{config: config, access_token: access_token} do
      access_token = Map.put(access_token, "id_token", "invalid")

      assert {:error, %Assent.Strategy.OIDC.InvalidIDTokenError{}} =
               OIDC.fetch_userinfo(config, access_token)
    end

    test "with missing `userinfo_endpoint` in OpenID configuration", %{
      config: config,
      access_token: access_token
    } do
      openid_configuration = Map.delete(config[:openid_configuration], "userinfo_endpoint")
      config = Keyword.put(config, :openid_configuration, openid_configuration)

      assert {:error, %InvalidOpenIDConfigurationError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `userinfo_endpoint` in OpenID Provider configuration"
    end

    test "with unreachable `userinfo_endpoint` URL", %{config: config, access_token: access_token} do
      openid_configuration =
        Map.put(
          config[:openid_configuration],
          "userinfo_endpoint",
          "http://localhost:8888/userinfo"
        )

      config = Keyword.put(config, :openid_configuration, openid_configuration)

      assert {:error, %ServerUnreachableError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request.url == "http://localhost:8888/userinfo"
      assert {:failed_connect, _} = error.reason
    end

    test "with unexpected `userinfo_endpoint` URL response", %{
      config: config,
      access_token: access_token
    } do
      expect_oidc_userinfo_request(gen_id_token(alg: "HS256"), status_code: 201)

      assert {:error, %UnexpectedResponseError{}} = OIDC.fetch_userinfo(config, access_token)
    end

    test "with unauthorized `userinfo_endpoint` URL response", %{
      config: config,
      access_token: access_token
    } do
      expect_oidc_userinfo_request(%{"error" => "Unauthorized"}, status_code: 401)

      assert {:error, %RequestError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) =~ "unauthorized token"
      assert error.response.status == 401
    end

    test "with JWT response with missing `:userinfo_signed_response_alg` config", %{
      config: config,
      access_token: access_token
    } do
      config = Keyword.delete(config, :userinfo_signed_response_alg)
      expect_oidc_userinfo_request(gen_id_token(alg: "HS256"))

      assert {:error, %MissingConfigError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert error.key == :userinfo_signed_response_alg
    end

    test "with JWT response with missing `:client_id` config", %{
      config: config,
      access_token: access_token
    } do
      config = Keyword.delete(config, :client_id)

      assert {:error, %MissingConfigError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert error.key == :client_id
    end

    test "with JWT response with missing `issuer` in OpenID configuration", %{
      config: config,
      access_token: access_token
    } do
      openid_config = Map.delete(Keyword.get(config, :openid_configuration), "issuer")
      config = Keyword.put(config, :openid_configuration, openid_config)

      assert {:error, %InvalidOpenIDConfigurationError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) == "expected `issuer` in OpenID Provider configuration"
    end

    test "with JWT response with JWT verification error", %{
      config: config,
      access_token: access_token
    } do
      [header, payload, _signature] = String.split(gen_id_token(alg: "HS256"), ".")
      expect_oidc_userinfo_request("#{header}.#{payload}.invalid")

      assert {:error, %InvalidUserInfoError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) == "expected JWT signature to be valid"
    end

    for key <- ~w(iss aud) do
      test "with JWT response with missing `#{key}`", %{
        config: config,
        access_token: access_token
      } do
        expected_keys = ~w(aud exp iat iss sub) -- [unquote(key)]
        id_token = gen_id_token(alg: "HS256", claims: %{unquote(key) => nil})
        expect_oidc_userinfo_request(id_token)

        assert {:error, %InvalidUserInfoError{} = error} =
                 OIDC.fetch_userinfo(config, access_token)

        assert Exception.message(error) ==
                 "expected `#{unquote(key)}` in claims, got: #{inspect(expected_keys)}"
      end
    end

    test "with JWT response with invalid `iss`", %{
      config: config,
      access_token: access_token
    } do
      id_token = gen_id_token(alg: "HS256", claims: %{"iss" => "invalid"})
      expect_oidc_userinfo_request(id_token)

      assert {:error, %InvalidUserInfoError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `iss` in claims to be trusted, got: \"invalid\""
    end

    test "with JWT response with `iss` not `:client_id` config value nor in `:trusted_issuers` config",
         %{
           config: config,
           access_token: access_token
         } do
      config = Keyword.put(config, :trusted_issuers, ["https://example.com"])
      id_token = gen_id_token(alg: "HS256", iss: "https://untrusted.com")
      expect_oidc_userinfo_request(id_token)

      assert {:error, %InvalidUserInfoError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `iss` in claims to be trusted, got: \"https://untrusted.com\""
    end

    test "with JWT response with `iss` in `:trusted_issuers` config", %{
      config: config,
      access_token: access_token
    } do
      config = Keyword.put(config, :trusted_issuers, ["https://example.com"])
      id_token = gen_id_token(alg: "HS256", iss: "https://example.com")
      expect_oidc_userinfo_request(id_token)

      assert {:ok, _userinfo} = OIDC.fetch_userinfo(config, access_token)
    end

    test "with JWT response with invalid `aud`", %{
      config: config,
      access_token: access_token
    } do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => "invalid"})
      expect_oidc_userinfo_request(id_token)

      assert {:error, %InvalidUserInfoError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to include `:client_id`, got: [\"invalid\"]"
    end

    test "with JWT response with `aud` case mismatch", %{
      config: config,
      access_token: access_token
    } do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => String.upcase(config[:client_id])})
      expect_oidc_userinfo_request(id_token)

      assert {:error, %InvalidUserInfoError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to include `:client_id`, got: [\"ID\"]"
    end

    test "with JWT response with `aud` list missing `:client_id` config value", %{
      config: config,
      access_token: access_token
    } do
      config = Keyword.put(config, :trusted_audiences, ~w(aud1 aud2))
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(aud1 aud2)})
      expect_oidc_userinfo_request(id_token)

      assert {:error, %InvalidUserInfoError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to include `:client_id`, got: [\"aud1\", \"aud2\"]"
    end

    test "with JWT response with `aud` list and missing `:trusted_audiences` config", %{
      config: config,
      access_token: access_token
    } do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(id aud1 aud2)})
      expect_oidc_userinfo_request(id_token)

      assert {:error, %InvalidUserInfoError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to contain only trusted audiences, got: [\"id\", \"aud1\", \"aud2\"]"
    end

    test "with JWT response with `aud` list containing untrusted audiences", %{
      config: config,
      access_token: access_token
    } do
      config = Keyword.put(config, :trusted_audiences, ~w(aud1))
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(id aud1 aud2)})
      expect_oidc_userinfo_request(id_token)

      assert {:error, %InvalidUserInfoError{} = error} = OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `aud` in claims to contain only trusted audiences, got: [\"id\", \"aud1\", \"aud2\"]"
    end

    test "with JWT response with `aud` list", %{config: config, access_token: access_token} do
      config = Keyword.put(config, :trusted_audiences, ~w(aud1 aud2))
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => ~w(id aud1 aud2)})
      expect_oidc_userinfo_request(id_token)

      assert {:ok, _} = OIDC.fetch_userinfo(config, access_token)
    end

    test "with JWT response", %{config: config, access_token: access_token} do
      expect_oidc_userinfo_request(gen_id_token(alg: "HS256"))

      assert {:ok, %{"sub" => "1"}} = OIDC.fetch_userinfo(config, access_token)
    end

    test "with JWT response with dynamic OpenID configuration", %{config: config} do
      config = Keyword.delete(config, :openid_configuration)
      id_token = gen_id_token(alg: "HS256", iss: config[:base_url])
      access_token = %{"access_token" => "access_token", "id_token" => id_token}

      openid_config = %{
        "issuer" => config[:base_url],
        "userinfo_endpoint" => TestServer.url("/userinfo")
      }

      expect_openid_config_request(openid_config)
      expect_oidc_userinfo_request(gen_id_token(alg: "HS256", iss: config[:base_url]))

      assert {:ok, _} = OIDC.fetch_userinfo(config, access_token)
    end

    test "with missing `sub` in UserInfo claims", %{config: config, access_token: access_token} do
      expect_oidc_userinfo_request(Map.delete(@user_claims, :sub))

      assert {:error, %InvalidUserInfoError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) ==
               "expected `sub` in claims, got: [\"email\", \"email_verified\", \"http://localhost:4000/additional\", \"name\"]"
    end

    test "with different `sub` in UserInfo claims", %{config: config, access_token: access_token} do
      expect_oidc_userinfo_request(Map.put(@user_claims, :sub, "2"))

      assert {:error, %InvalidUserInfoError{} = error} =
               OIDC.fetch_userinfo(config, access_token)

      assert Exception.message(error) == "expected `sub` in claims to match `sub` in ID Token"
    end
  end
end
