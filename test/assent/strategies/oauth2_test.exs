defmodule Assent.Strategy.OAuth2Test do
  use Assent.Test.OAuth2TestCase

  alias Assent.{CallbackCSRFError, CallbackError, Config.MissingKeyError, RequestError, Strategy.OAuth2}

  @client_id "id"
  @client_secret "secret"
  @private_key_id "key_id"
  @private_key """
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
  @public_key """
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

  test "authorize_url/2", %{config: config, bypass: bypass} do
    assert {:ok, %{url: url, session_params: %{state: state}}} =
      config
      |> Keyword.put(:client_id, @client_id)
      |> OAuth2.authorize_url()

    refute is_nil(state)
    assert url =~ "http://localhost:#{bypass.port}/oauth/authorize?client_id=#{@client_id}&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&state=#{state}"
  end

  describe "callback/2" do
    setup %{config: config} do
      config =
        config
        |> Keyword.put(:client_id, @client_id)
        |> Keyword.put(:client_secret, @client_secret)
        |> Keyword.put(:user_url, "/api/user")

      {:ok, config: config}
    end

    @user_api_params %{name: "Dan Schultzer", email: "foo@example.com", uid: "1"}

    test "with `:client_secret_basic` auth method", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, [], fn conn, params ->
        assert [{"authorization", "Basic " <> token} | _rest] = conn.req_headers
        assert Base.url_decode64(token, padding: false) == {:ok, "#{@client_id}:#{@client_secret}"}

        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "test"
        assert params["redirect_uri"] == "test"
      end)

      expect_oauth2_user_request(bypass, @user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:client_secret_post` auth method", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :auth_method, :client_secret_post)

      expect_oauth2_access_token_request(bypass, [], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "test"
        assert params["redirect_uri"] == "test"
        assert params["client_id"] == @client_id
        assert params["client_secret"] == @client_secret
      end)

      expect_oauth2_user_request(bypass, @user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:client_secret_jwt` auth method", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :auth_method, :client_secret_jwt)

      expect_oauth2_access_token_request(bypass, [], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "test"
        assert params["redirect_uri"] == "test"
        assert params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        assert {:ok, jwt} = Assent.JWTAdapter.AssentJWT.verify(params["client_assertion"], @client_secret, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["alg"] == "HS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.claims["iss"] == @client_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == "http://localhost:#{bypass.port}"
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oauth2_user_request(bypass, @user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:private_key_jwt` auth method", %{config: config, callback_params: params, bypass: bypass} do
      config =
        config
        |> Keyword.delete(:client_secret)
        |> Keyword.put(:auth_method, :private_key_jwt)
        |> Keyword.put(:private_key, @private_key)
        |> Keyword.put(:private_key_id, @private_key_id)

      expect_oauth2_access_token_request(bypass, [], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "test"
        assert params["redirect_uri"] == "test"
        assert params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        assert {:ok, jwt} = Assent.JWTAdapter.AssentJWT.verify(params["client_assertion"], @public_key, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["alg"] == "RS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == @private_key_id
        assert jwt.claims["iss"] == @client_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == "http://localhost:#{bypass.port}"
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oauth2_user_request(bypass, @user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:private_key_jwt` auth method with private key as file", %{config: config, callback_params: params, bypass: bypass} do
      File.mkdir("tmp/")
      File.write!("tmp/private-key.pem", @private_key)

      config =
        config
        |> Keyword.delete(:client_secret)
        |> Keyword.put(:auth_method, :private_key_jwt)
        |> Keyword.put(:private_key_path, "tmp/private-key.pem")
        |> Keyword.put(:private_key_id, @private_key_id)

      expect_oauth2_access_token_request(bypass, [], fn _conn, params ->
        assert {:ok, jwt} = Assent.JWTAdapter.AssentJWT.verify(params["client_assertion"], @public_key, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["kid"] == @private_key_id
      end)

      expect_oauth2_user_request(bypass, @user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "normalizes data", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass)
      expect_oauth2_user_request(bypass, @user_api_params)

      assert {:ok, %{user: user, token: token}} = OAuth2.callback(config, params)
      assert user == %{"email" => "foo@example.com", "name" => "Dan Schultzer", "uid" => "1"}
      assert token == %{"access_token" => "access_token"}
    end

    test "with redirect error", %{config: config} do
      params = %{"error" => "access_denied", "error_description" => "The user denied the request", "state" => "test"}

      assert {:error, %CallbackError{message: "The user denied the request", error: "access_denied", error_uri: nil}} = OAuth2.callback(config, params)
    end

    test "with invalid state", %{config: config, callback_params: params} do
      params = Map.put(params, "state", "invalid")

      assert {:error, %CallbackCSRFError{}} = OAuth2.callback(config, params)
    end

    test "access token error with 200 response", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, params: %{"error" => "error", "error_description" => "Error description"})

      assert {:error, %RequestError{error: :unexpected_response}} = OAuth2.callback(config, params)
    end

    test "access token error with 500 response", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, status_code: 500, params: %{error: "Error"})

      assert {:error, %RequestError{error: :invalid_server_response}} = OAuth2.callback(config, params)
    end

    test "configuration error", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.delete(config, :user_url)

      expect_oauth2_access_token_request(bypass)

      assert {:error, %MissingKeyError{message: "Key `:user_url` not found in config"}} = OAuth2.callback(config, params)
    end

    test "user url connection error", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :user_url, "http://localhost:8888/api/user")

      expect_oauth2_access_token_request(bypass)

      assert {:error, %Assent.RequestError{error: :unreachable}} = OAuth2.callback(config, params)
    end

    test "user url unauthorized access token", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass)
      expect_oauth2_user_request(bypass, %{"error" => "Unauthorized"}, status_code: 401)

      assert {:error, %RequestError{message: "Unauthorized token"}} = OAuth2.callback(config, params)
    end
  end
end
