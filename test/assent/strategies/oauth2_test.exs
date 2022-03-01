defmodule Assent.Strategy.OAuth2Test do
  use Assent.Test.OAuth2TestCase

  alias Assent.{CallbackCSRFError, CallbackError, Config.MissingKeyError, JWTAdapter.AssentJWT, MissingParamError, RequestError, Strategy.OAuth2, TestServer}

  @client_id "s6BhdRkqt3"
  @client_secret "7Fjfp0ZBr1KtDRbnfVdmIw"
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

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url, session_params: %{state: state}}} =
      config
      |> Keyword.put(:client_id, @client_id)
      |> OAuth2.authorize_url()

    refute is_nil(state)
    assert url =~ TestServer.url("/oauth/authorize?client_id=#{@client_id}&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&state=#{state}")
  end

  test "authorize_url/2 with state in authorization_param", %{config: config} do
    assert {:ok, %{session_params: %{state: state}}} =
      config
      |> Keyword.put(:client_id, @client_id)
      |> Keyword.put(:authorization_params, state: "state_test_value")
      |> OAuth2.authorize_url()

    assert state == "state_test_value"
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

    test "with missing `:session_params` config", %{config: config, callback_params: params} do
      config = Keyword.delete(config, :session_params)

      assert {:error, %MissingKeyError{} = error} = OAuth2.callback(config, params)
      assert error.message == "Key `:session_params` not found in config"
    end

    test "with error params", %{config: config, callback_params: %{"state" => state}} do
      params = %{"error" => "access_denied", "error_description" => "The user denied the request", "state" => state}

      assert {:error, %CallbackError{} = error} = OAuth2.callback(config, params)
      assert error.message == "The user denied the request"
      assert error.error == "access_denied"
      refute error.error_uri
    end

    test "with missing code param", %{config: config, callback_params: params} do
      params = Map.delete(params, "code")

      assert {:error, %MissingParamError{} = error} = OAuth2.callback(config, params)
      assert error.message == "Expected \"code\" to exist in params, but only found the following keys: [\"state\"]"
      assert error.params == %{"state" => "state_test_value"}
    end

    test "with missing state param", %{config: config, callback_params: params} do
      params = Map.delete(params, "state")

      assert {:error, %MissingParamError{} = error} = OAuth2.callback(config, params)
      assert error.message == "Expected \"state\" to exist in params, but only found the following keys: [\"code\"]"
      assert error.params == %{"code" => "code_test_value"}
    end

    test "with invalid state param", %{config: config, callback_params: params} do
      params = Map.put(params, "state", "invalid")

      assert {:error, %CallbackCSRFError{} = error} = OAuth2.callback(config, params)
      assert error.message == "CSRF detected with param key \"state\""
    end

    test "with state param without state in session_params", %{config: config, callback_params: params} do
      config = Keyword.put(config, :session_params, %{})

      expect_oauth2_access_token_request([])
      expect_oauth2_user_request(%{})

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "without state in params and session params", %{config: config, callback_params: params} do
      config = Keyword.put(config, :session_params, %{})
      params = Map.delete(params, "state")

      expect_oauth2_access_token_request([])
      expect_oauth2_user_request(%{})

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with unreachable token url", %{config: config, callback_params: params} do
      TestServer.down()

      assert {:error, %RequestError{} = error} = OAuth2.callback(config, params)
      assert error.error == :unreachable
      assert error.message =~ "Server was unreachable with Assent.HTTPAdapter.Httpc."
      assert error.message =~ "{:failed_connect"
      assert error.message =~ "URL: #{TestServer.url("/oauth/token")}"
    end

    test "with access token error with 200 response", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(params: %{"error" => "error", "error_description" => "Error description"})

      assert {:error, %RequestError{} = error} = OAuth2.callback(config, params)
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:"
      assert error.message =~ "%{\"error\" => \"error\", \"error_description\" => \"Error description\"}"
    end

    test "with access token error with 500 response", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(status_code: 500, params: %{error: "Error"})

      assert {:error, %RequestError{} = error} = OAuth2.callback(config, params)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error\" => \"Error\"}"
    end

    test "with missing `:user_url`", %{config: config, callback_params: params} do
      config = Keyword.delete(config, :user_url)

      expect_oauth2_access_token_request()

      assert {:error, %MissingKeyError{} = error} = OAuth2.callback(config, params)
      assert error.message == "Key `:user_url` not found in config"
    end

    test "with invalid token type", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(params: %{access_token: "access_token", token_type: "invalid"})

      assert OAuth2.callback(config, params) == {:error, "Authorization with token type `invalid` not supported"}
    end

    test "with unreachable `:user_url`", %{config: config, callback_params: params} do
      config = Keyword.put(config, :user_url, "http://localhost:8888/api/user")

      expect_oauth2_access_token_request()

      assert {:error, %RequestError{} = error} = OAuth2.callback(config, params)
      assert error.error == :unreachable
      assert error.message =~ "Server was unreachable with Assent.HTTPAdapter.Httpc."
      assert error.message =~ "{:failed_connect"
      assert error.message =~ "URL: http://localhost:8888/api/user"
    end

    test "with unauthorized `:user_url`", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request()
      expect_oauth2_user_request(%{"error" => "Unauthorized"}, status_code: 401)

      assert {:error, %RequestError{} = error} = OAuth2.callback(config, params)
      assert error.message == "Unauthorized token"
      refute error.error
    end

    @user_api_params %{name: "Dan Schultzer", email: "foo@example.com", uid: "1"}

    test "with no auth method", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "code_test_value"
        assert params["redirect_uri"] == "http://localhost:4000/auth/callback"
        assert params["client_id"] == @client_id
        refute params["client_secret"]
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:client_secret_basic` auth method", %{config: config, callback_params: params} do
      config = Keyword.put(config, :auth_method, :client_secret_basic)

      expect_oauth2_access_token_request([], fn conn, params ->
        assert [{"authorization", "Basic " <> token} | _rest] = conn.req_headers
        assert Base.url_decode64(token) == {:ok, "#{@client_id}:#{@client_secret}"}

        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "code_test_value"
        assert params["redirect_uri"] == "http://localhost:4000/auth/callback"
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:client_secret_post` auth method", %{config: config, callback_params: params} do
      config = Keyword.put(config, :auth_method, :client_secret_post)

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "code_test_value"
        assert params["redirect_uri"] == "http://localhost:4000/auth/callback"
        assert params["client_id"] == @client_id
        assert params["client_secret"] == @client_secret
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:client_secret_jwt` auth method", %{config: config, callback_params: params} do
      config = Keyword.put(config, :auth_method, :client_secret_jwt)

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "code_test_value"
        assert params["redirect_uri"] == "http://localhost:4000/auth/callback"
        assert params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        assert {:ok, jwt} = AssentJWT.verify(params["client_assertion"], @client_secret, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["alg"] == "HS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.claims["iss"] == @client_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == TestServer.url()
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:private_key_jwt` auth method", %{config: config, callback_params: params} do
      config =
        config
        |> Keyword.delete(:client_secret)
        |> Keyword.put(:auth_method, :private_key_jwt)
        |> Keyword.put(:private_key, @private_key)
        |> Keyword.put(:private_key_id, @private_key_id)

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "code_test_value"
        assert params["redirect_uri"] == "http://localhost:4000/auth/callback"
        assert params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        assert {:ok, jwt} = AssentJWT.verify(params["client_assertion"], @public_key, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["alg"] == "RS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == @private_key_id
        assert jwt.claims["iss"] == @client_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == TestServer.url()
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:private_key_jwt` auth method with private key as file", %{config: config, callback_params: params} do
      File.mkdir("tmp/")
      File.write!("tmp/private-key.pem", @private_key)

      config =
        config
        |> Keyword.delete(:client_secret)
        |> Keyword.put(:auth_method, :private_key_jwt)
        |> Keyword.put(:private_key_path, "tmp/private-key.pem")
        |> Keyword.put(:private_key_id, @private_key_id)

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert {:ok, jwt} = AssentJWT.verify(params["client_assertion"], @public_key, json_library: Jason)
        assert jwt.verified?
        assert jwt.header["kid"] == @private_key_id
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "normalizes data", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request()
      expect_oauth2_user_request(@user_api_params)

      assert {:ok, %{user: user, token: token}} = OAuth2.callback(config, params)
      assert user == %{"email" => "foo@example.com", "name" => "Dan Schultzer", "uid" => "1"}
      assert token == %{"access_token" => "access_token"}
    end
  end

  describe "refresh_access_token/3" do
    setup %{config: config} do
      config =
        config
        |> Keyword.put(:client_id, @client_id)
        |> Keyword.put(:client_secret, @client_secret)

      {:ok, config: config}
    end

    test "with missing `refreh_token` in token", %{config: config} do
      assert OAuth2.refresh_access_token(config, %{}) == {:error, "No `refresh_token` in token map"}
    end

    test "with refresh token error with 200 response", %{config: config} do
      expect_oauth2_access_token_request(params: %{"error" => "error", "error_description" => "Error description"})

      assert {:error, %RequestError{} = error} = OAuth2.refresh_access_token(config, %{"refresh_token" => "refresh_token_test_value"})
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:"
      assert error.message =~ "%{\"error\" => \"error\", \"error_description\" => \"Error description\"}"
    end

    test "with fresh token error with 500 response", %{config: config} do
      expect_oauth2_access_token_request(status_code: 500, params: %{error: "Error"})

      assert {:error, %RequestError{} = error} = OAuth2.refresh_access_token(config, %{"refresh_token" => "refresh_token_test_value"})
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error\" => \"Error\"}"
    end

    test "returns token", %{config: config} do
      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "refresh_token"
        assert params["refresh_token"] == "refresh_token_test_value"
        assert params["client_id"] == @client_id
        refute params["client_secret"]
      end)

      assert {:ok, token} = OAuth2.refresh_access_token(config, %{"refresh_token" => "refresh_token_test_value"})
      assert token == %{"access_token" => "access_token"}
    end

    test "with additional params", %{config: config} do
      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "refresh_token"
        assert params["refresh_token"] == "refresh_token_test_value"
        assert params["scope"] == "test"
      end)

      assert {:ok, _any} = OAuth2.refresh_access_token(config, %{"refresh_token" => "refresh_token_test_value"}, scope: "test")
    end
  end

  describe "request/6 as GET request" do
    setup do
      {:ok, token: %{"access_token" => "access_token"}}
    end

    test "with missing `:site` config", %{config: config, token: token} do
      config = Keyword.delete(config, :site)

      assert OAuth2.request(config, token, :get, "/info") == {:error, %MissingKeyError{message: "Key `:site` not found in config"}}
    end

    test "with missing `access_token` in token", %{config: config, token: token} do
      token =  Map.delete(token, "access_token")

      assert OAuth2.request(config, token, :get, "/info") == {:error, "No `access_token` in token map"}
      assert OAuth2.request(config, Map.put(token, "token_type", "bearer"), :get, "/info") == {:error, "No `access_token` in token map"}
    end

    test "with invalid `token_type` in token", %{config: config, token: token} do
      assert OAuth2.request(config, Map.put(token, "token_type", "invalid"), :get, "/info") == {:error, "Authorization with token type `invalid` not supported"}
    end

    test "gets", %{config: config, token: token} do
      expect_oauth2_api_request("/info", %{"success" => true})

      assert {:ok, response} = OAuth2.request(config, token, :get, "/info")
      assert response.body == %{"success" => true}

      expect_oauth2_api_request("/info", %{"success" => true}, [], fn conn ->
        assert conn.params["a"] == "1"
      end)

      assert {:ok, response} = OAuth2.request(config, token, :get, "/info", a: 1)
      assert response.body == %{"success" => true}

      expect_oauth2_api_request("/info", %{"success" => true}, [], fn conn ->
        assert Plug.Conn.get_req_header(conn, "b") == ["2"]
      end)

      assert {:ok, response} = OAuth2.request(config, token, :get, "/info", [a: 1], [{"b", "2"}])
      assert response.body == %{"success" => true}
    end

    test "with `token_type=bearer` in token", %{config: config, token: token} do
      expect_oauth2_api_request("/info", %{"success" => true})
      assert {:ok, response} = OAuth2.request(config, Map.put(token, "token_type", "bearer"), :get, "/info")
      assert response.body == %{"success" => true}
    end

    test "with `token_type=Bearer` in token", %{config: config, token: token} do
      expect_oauth2_api_request("/info", %{"success" => true})
      assert {:ok, response} = OAuth2.request(config, Map.put(token, "token_type", "Bearer"), :get, "/info")
      assert response.body == %{"success" => true}
    end
  end

  test "request/6 as POST request", %{config: config} do
    token = %{"access_token" => "access_token"}

    expect_oauth2_api_request("/info", %{"success" => true}, [], nil, "POST")

    assert {:ok, response} = OAuth2.request(config, token, :post, "/info")
    assert response.body == %{"success" => true}

    expect_oauth2_api_request("/info", %{"success" => true}, [], fn conn ->
      {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
      params = URI.decode_query(body)

      assert params["a"] == "1"
    end, "POST")

    assert {:ok, response} = OAuth2.request(config, token, :post, "/info", [a: 1])
    assert response.body == %{"success" => true}
  end
end
