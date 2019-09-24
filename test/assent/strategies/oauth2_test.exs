defmodule Assent.Strategy.OAuth2Test do
  use Assent.Test.OAuth2TestCase

  alias Assent.{CallbackCSRFError, CallbackError, Config.MissingKeyError, RequestError, Strategy.OAuth2}

  test "authorize_url/2", %{config: config, bypass: bypass} do
    assert {:ok, %{url: url, session_params: %{state: state}}} = OAuth2.authorize_url(config)

    refute is_nil(state)
    assert url =~ "http://localhost:#{bypass.port}/oauth/authorize?client_id=id&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&state=#{state}"
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :user_url, "/api/user")

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, [], fn conn ->
        {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        assert params["grant_type"] == "authorization_code"
        assert params["response_type"] == "code"
        assert params["code"] == "test"
        assert params["client_secret"] == "secret"
        assert params["redirect_uri"] == "test"
      end)

      expect_oauth2_user_request(bypass, %{name: "Dan Schultzer", email: "foo@example.com", uid: "1"})

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
