defmodule Assent.Strategy.OAuth2Test do
  use Assent.Test.OAuth2TestCase

  alias Assent.InvalidResponseError
  alias Assent.ServerUnreachableError
  alias Assent.UnexpectedResponseError

  alias Assent.{
    CallbackCSRFError,
    CallbackError,
    Config.MissingKeyError,
    JWTAdapter.AssentJWT,
    MissingParamError,
    RequestError,
    Strategy.OAuth2
  }

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
    assert {:ok, %{url: url, session_params: session_params}} =
             config
             |> Keyword.put(:client_id, @client_id)
             |> OAuth2.authorize_url()

    assert session_params.state
    assert url =~ TestServer.url("/oauth/authorize?")

    query_params = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert query_params == %{
             "client_id" => @client_id,
             "redirect_uri" => "http://localhost:4000/auth/callback",
             "response_type" => "code",
             "state" => session_params.state
           }
  end

  test "authorize_url/2 with `state: binary`", %{config: config} do
    assert {:ok, %{session_params: session_params}} =
             config
             |> Keyword.put(:state, "custom_state")
             |> OAuth2.authorize_url()

    assert session_params.state == "custom_state"
  end

  test "authorize_url/2 with `state: false`", %{config: config} do
    assert {:ok, %{session_params: session_params}} =
             config
             |> Keyword.put(:state, false)
             |> OAuth2.authorize_url()

    assert session_params == %{}
  end

  test "authorize_url/2 with `code_verifier: true`", %{config: config} do
    assert {:ok, %{url: url, session_params: session_params}} =
             config
             |> Keyword.put(:code_verifier, true)
             |> OAuth2.authorize_url()

    assert session_params.code_verifier
    assert String.length(session_params.code_verifier) == 128

    assert session_params.code_challenge ==
             Base.url_encode64(:crypto.hash(:sha256, session_params.code_verifier),
               padding: false
             )

    assert session_params.code_challenge_method == "S256"

    query_params = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert query_params["code_challenge"] == session_params.code_challenge
    assert query_params["code_challenge_method"] == session_params.code_challenge_method
    refute query_params["code_verifier"]
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
      assert error.key == :session_params
    end

    test "with error params", %{config: config, callback_params: %{"state" => state}} do
      params = %{
        "error" => "access_denied",
        "error_description" => "The user denied the request",
        "state" => state
      }

      assert {:error, %CallbackError{} = error} = OAuth2.callback(config, params)
      assert error.message == "The user denied the request"
      assert error.error == "access_denied"
      refute error.error_uri
    end

    test "with missing code param", %{config: config, callback_params: params} do
      params = Map.delete(params, "code")

      assert {:error, %MissingParamError{} = error} = OAuth2.callback(config, params)
      assert Exception.message(error) == "Expected \"code\" in params, got: [\"state\"]"
      assert error.expected_key == "code"
      assert error.params == %{"state" => "state_test_value"}
    end

    test "with missing state param", %{config: config, callback_params: params} do
      params = Map.delete(params, "state")

      assert {:error, %MissingParamError{} = error} = OAuth2.callback(config, params)
      assert Exception.message(error) == "Expected \"state\" in params, got: [\"code\"]"
      assert error.expected_key == "state"
      assert error.params == %{"code" => "code_test_value"}
    end

    test "with invalid state param", %{config: config, callback_params: params} do
      params = Map.put(params, "state", "invalid")

      assert {:error, %CallbackCSRFError{} = error} = OAuth2.callback(config, params)
      assert Exception.message(error) == "CSRF detected with param key \"state\""
      assert error.key == "state"
    end

    test "with missing state in session_params", %{
      config: config,
      callback_params: params
    } do
      config = Keyword.put(config, :session_params, %{})

      assert_raise KeyError, fn ->
        OAuth2.callback(config, params)
      end
    end

    test "with `state: false`", %{config: config, callback_params: params} do
      config =
        config
        |> Keyword.put(:session_params, %{})
        |> Keyword.put(:state, false)

      params = Map.delete(params, "state")

      expect_oauth2_access_token_request([])
      expect_oauth2_user_request(%{})

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `state: binary`", %{config: config, callback_params: params} do
      session_params = Map.put(config[:session_params], :state, "custom_state")

      config =
        config
        |> Keyword.put(:state, "custom_state")
        |> Keyword.put(:session_params, session_params)

      params = Map.put(params, "state", "custom_state")

      expect_oauth2_access_token_request([])
      expect_oauth2_user_request(%{})

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `code_verifier: true` with missing code_verifier in session params", %{
      config: config,
      callback_params: params
    } do
      config = Keyword.put(config, :code_verifier, true)

      assert_raise KeyError, fn ->
        OAuth2.callback(config, params)
      end
    end

    test "with `code_verifier: true`", %{config: config, callback_params: params} do
      session_params = Map.put(config[:session_params], :code_verifier, "code_verifier_value")

      config =
        config
        |> Keyword.put(:code_verifier, true)
        |> Keyword.put(:session_params, session_params)

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["code_verifier"] == "code_verifier_value"
        refute params["code_challenge"]
        refute params["code_challenge_method"]
      end)

      expect_oauth2_user_request(%{})

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with unreachable token url", %{config: config, callback_params: params} do
      oauth_token_url = TestServer.url("/oauth/token")
      TestServer.stop()

      assert {:error, %ServerUnreachableError{} = error} = OAuth2.callback(config, params)
      assert Exception.message(error) =~ "The server was unreachable."
      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request_url == oauth_token_url
      assert {:failed_connect, _} = error.reason
    end

    test "with access token error with 200 response", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(
        params: %{"error" => "error", "error_description" => "Error description"}
      )

      assert {:error, %UnexpectedResponseError{} = error} = OAuth2.callback(config, params)
      assert Exception.message(error) =~ "An unexpected response was received."

      assert error.response.body == %{
               "error" => "error",
               "error_description" => "Error description"
             }
    end

    test "with access token error with 500 response", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(status_code: 500, params: %{error: "Error"})

      assert {:error, %InvalidResponseError{} = error} = OAuth2.callback(config, params)
      assert error.response.status == 500
      assert error.response.body == %{"error" => "Error"}
    end

    test "with missing `:user_url`", %{config: config, callback_params: params} do
      config = Keyword.delete(config, :user_url)

      expect_oauth2_access_token_request()

      assert {:error, %MissingKeyError{} = error} = OAuth2.callback(config, params)
      assert error.key == :user_url
    end

    test "with invalid token type", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(
        params: %{access_token: "access_token", token_type: "invalid"}
      )

      assert OAuth2.callback(config, params) ==
               {:error, "Authorization with token type `invalid` not supported"}
    end

    test "with unreachable `:user_url`", %{config: config, callback_params: params} do
      config = Keyword.put(config, :user_url, "http://localhost:8888/api/user")

      expect_oauth2_access_token_request()

      assert {:error, %ServerUnreachableError{} = error} = OAuth2.callback(config, params)
      assert Exception.message(error) =~ "The server was unreachable."
      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request_url == config[:user_url]
      assert {:failed_connect, _} = error.reason
    end

    test "with unauthorized `:user_url`", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request()
      expect_oauth2_user_request(%{"error" => "Unauthorized"}, status_code: 401)

      assert {:error, %RequestError{} = error} = OAuth2.callback(config, params)
      assert error.message == "Unauthorized token"
      assert error.response.status == 401
      assert error.response.body == %{"error" => "Unauthorized"}
    end

    test "with `:user_url` not returning decoded map in body", %{
      config: config,
      callback_params: params
    } do
      expect_oauth2_access_token_request()
      expect_oauth2_user_request("%")

      assert {:error, %UnexpectedResponseError{} = error} = OAuth2.callback(config, params)
      assert Exception.message(error) =~ "An unexpected response was received."
      assert error.response.body == "%"
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
        assert ["Basic " <> token] = Plug.Conn.get_req_header(conn, "authorization")
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
      url = TestServer.url()

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "code_test_value"
        assert params["redirect_uri"] == "http://localhost:4000/auth/callback"

        assert params["client_assertion_type"] ==
                 "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        assert {:ok, jwt} =
                 AssentJWT.verify(
                   params["client_assertion"],
                   @client_secret,
                   json_library: @json_library
                 )

        assert jwt.verified?
        assert jwt.header["alg"] == "HS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.claims["iss"] == @client_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == url
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

      url = TestServer.url()

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "authorization_code"
        assert params["code"] == "code_test_value"
        assert params["redirect_uri"] == "http://localhost:4000/auth/callback"

        assert params["client_assertion_type"] ==
                 "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

        assert {:ok, jwt} =
                 AssentJWT.verify(
                   params["client_assertion"],
                   @public_key,
                   json_library: @json_library
                 )

        assert jwt.verified?
        assert jwt.header["alg"] == "RS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == @private_key_id
        assert jwt.claims["iss"] == @client_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == url
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:private_key_jwt` auth method with private key as file", %{
      config: config,
      callback_params: params
    } do
      File.mkdir_p!("tmp/")
      File.write!("tmp/private-key.pem", @private_key)

      config =
        config
        |> Keyword.delete(:client_secret)
        |> Keyword.put(:auth_method, :private_key_jwt)
        |> Keyword.put(:private_key_path, "tmp/private-key.pem")
        |> Keyword.put(:private_key_id, @private_key_id)

      expect_oauth2_access_token_request([], fn _conn, params ->
        assert {:ok, jwt} =
                 AssentJWT.verify(
                   params["client_assertion"],
                   @public_key,
                   json_library: @json_library
                 )

        assert jwt.verified?
        assert jwt.header["kid"] == @private_key_id
      end)

      expect_oauth2_user_request(@user_api_params)

      assert {:ok, _any} = OAuth2.callback(config, params)
    end

    test "with `:private_key_jwt` auth method with private key as missing file", %{
      config: config,
      callback_params: params
    } do
      config =
        config
        |> Keyword.delete(:client_secret)
        |> Keyword.put(:auth_method, :private_key_jwt)
        |> Keyword.put(:private_key_path, "tmp/missing.pem")
        |> Keyword.put(:private_key_id, @private_key_id)

      assert {:error, "Failed to read \"tmp/missing.pem\", got; :enoent"} =
               OAuth2.callback(config, params)
    end

    test "with 201 response", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request(status_code: 201)
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

    test "with missing `refresh_token` in token", %{config: config} do
      assert OAuth2.refresh_access_token(config, %{}) ==
               {:error, "No `refresh_token` in token map"}
    end

    test "with refresh token error with 200 response", %{config: config} do
      expect_oauth2_access_token_request(
        params: %{"error" => "error", "error_description" => "Error description"}
      )

      assert {:error, %UnexpectedResponseError{} = error} =
               OAuth2.refresh_access_token(config, %{
                 "refresh_token" => "refresh_token_test_value"
               })

      assert Exception.message(error) =~ "An unexpected response was received."

      assert error.response.body == %{
               "error" => "error",
               "error_description" => "Error description"
             }
    end

    test "with fresh token error with 500 response", %{config: config} do
      expect_oauth2_access_token_request(status_code: 500, params: %{error: "Error"})

      assert {:error, %InvalidResponseError{} = error} =
               OAuth2.refresh_access_token(config, %{
                 "refresh_token" => "refresh_token_test_value"
               })

      assert Exception.message(error) =~ "An invalid response was received."
      assert error.response.status == 500
      assert error.response.body == %{"error" => "Error"}
    end

    test "returns token", %{config: config} do
      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "refresh_token"
        assert params["refresh_token"] == "refresh_token_test_value"
        assert params["client_id"] == @client_id
        refute params["client_secret"]
      end)

      assert {:ok, token} =
               OAuth2.refresh_access_token(config, %{
                 "refresh_token" => "refresh_token_test_value"
               })

      assert token == %{"access_token" => "access_token"}
    end

    test "with additional params", %{config: config} do
      expect_oauth2_access_token_request([], fn _conn, params ->
        assert params["grant_type"] == "refresh_token"
        assert params["refresh_token"] == "refresh_token_test_value"
        assert params["scope"] == "test"
      end)

      assert {:ok, _any} =
               OAuth2.refresh_access_token(
                 config,
                 %{"refresh_token" => "refresh_token_test_value"},
                 scope: "test"
               )
    end
  end

  describe "request/6 as GET request" do
    setup do
      {:ok, token: %{"access_token" => "access_token"}}
    end

    test "with missing `:base_url` config", %{config: config, token: token} do
      config = Keyword.delete(config, :base_url)

      assert {:error, %MissingKeyError{} = error} = OAuth2.request(config, token, :get, "/info")
      assert error.key == :base_url
    end

    test "with missing `access_token` in token", %{config: config, token: token} do
      token = Map.delete(token, "access_token")

      assert OAuth2.request(config, token, :get, "/info") ==
               {:error, "No `access_token` in token map"}

      assert OAuth2.request(config, Map.put(token, "token_type", "bearer"), :get, "/info") ==
               {:error, "No `access_token` in token map"}
    end

    test "with invalid `token_type` in token", %{config: config, token: token} do
      assert OAuth2.request(config, Map.put(token, "token_type", "invalid"), :get, "/info") ==
               {:error, "Authorization with token type `invalid` not supported"}
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

      assert {:ok, response} =
               OAuth2.request(config, Map.put(token, "token_type", "bearer"), :get, "/info")

      assert response.body == %{"success" => true}
    end

    test "with `token_type=Bearer` in token", %{config: config, token: token} do
      expect_oauth2_api_request("/info", %{"success" => true})

      assert {:ok, response} =
               OAuth2.request(config, Map.put(token, "token_type", "Bearer"), :get, "/info")

      assert response.body == %{"success" => true}
    end
  end

  test "request/6 as POST request", %{config: config} do
    token = %{"access_token" => "access_token"}

    expect_oauth2_api_request("/info", %{"success" => true}, [], nil, "POST")

    assert {:ok, response} = OAuth2.request(config, token, :post, "/info")
    assert response.body == %{"success" => true}

    expect_oauth2_api_request(
      "/info",
      %{"success" => true},
      [],
      fn conn ->
        {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        assert params["a"] == "1"
      end,
      "POST"
    )

    assert {:ok, response} = OAuth2.request(config, token, :post, "/info", a: 1)
    assert response.body == %{"success" => true}
  end

  ## Deprecated

  test "authorize_url/2 with state in authorization_params", %{config: config} do
    assert {:ok, %{session_params: %{state: state}}} =
             config
             |> Keyword.put(:client_id, @client_id)
             |> Keyword.put(:authorization_params, state: "state_test_value")
             |> OAuth2.authorize_url()

    assert state == "state_test_value"
  end
end
