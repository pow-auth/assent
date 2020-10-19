defmodule Assent.Strategy.OAuthTest do
  use Assent.Test.OAuthTestCase

  alias Assent.{Config.MissingKeyError, RequestError, Strategy.OAuth}

  describe "authorize_url/2" do
    test "returns url", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}} = OAuth.authorize_url(config)
      refute is_nil(oauth_token_secret)
      assert url == "http://localhost:#{bypass.port}/oauth/authenticate?oauth_token=request_token"
    end

    test "parses URI query response with authorization params", %{config: config, bypass: bypass} do
      authorization_params = [scope: "reading writing", another_param: "param"]
      config = Keyword.put(config, :authorization_params, authorization_params)
      expect_oauth_request_token_request(bypass)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: _oauth_token_secret}}} = OAuth.authorize_url(config)
      assert url == "http://localhost:#{bypass.port}/oauth/authenticate?another_param=param&oauth_token=request_token&scope=reading+writing"
    end

    test "parses URI query response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, content_type: "text/html", params: URI.encode_query(%{oauth_token: "encoded_uri_request_token", oauth_token_secret: "encoded_uri_token_secret"}))

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: "encoded_uri_token_secret"}}} = OAuth.authorize_url(config)
      assert url == "http://localhost:#{bypass.port}/oauth/authenticate?oauth_token=encoded_uri_request_token"
    end

    test "bubbles up unexpected response with HTTP status 200", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, params: %{"error_code" => 215, "error_message" => "Bad Authentication data."})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:"
      assert error.message =~ "%{\"error_code\" => \"215\", \"error_message\" => \"Bad Authentication data.\"}"
    end

    test "bubbles up error response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, status_code: 500, params: %{"error_code" => 215, "error_message" => "Bad Authentication data."})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error_code\" => \"215\", \"error_message\" => \"Bad Authentication data.\"}"
    end

    test "bubbles up json error response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, status_code: 500, content_type: "application/json", params: %{"errors" => [%{"code" => 215, "message" => "Bad Authentication data."}]})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"errors\" => [%{\"code\" => 215, \"message\" => \"Bad Authentication data.\"}]}"
    end

    test "bubbles up network error", %{config: config, bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, %Assent.RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :unreachable
      assert error.message =~ "Server was unreachable with Assent.HTTPAdapter.Httpc."
      assert error.message =~ "{:failed_connect, "
      assert error.message =~ "URL: http://localhost:#{bypass.port}/oauth/request_token"
    end
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :user_url, "/api/user")

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth_access_token_request(bypass)
      expect_oauth_user_request(bypass, %{email: nil})

      assert {:ok, %{user: user, token: token}} = OAuth.callback(config, params)
      assert user == %{"email" => nil}
      assert token == %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}
    end

    test "with invalid verifier", %{config: config, callback_params: params, bypass: bypass} do
      params = Map.put(params, "oauth_verifier", "invalid")

      expect_oauth_access_token_request(bypass)

      assert {:error, %RequestError{} = error} = OAuth.callback(config, params)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error\" => \"Invalid signature\"}"
    end

    test "with invalid request token secret", %{config: config, callback_params: params, bypass: bypass} do
      config = Keyword.put(config, :session_params, %{oauth_token_secret: "invalid"})

      expect_oauth_access_token_request(bypass)

      assert {:error, %RequestError{} = error} = OAuth.callback(config, params)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error\" => \"Invalid signature\"}"
    end

    test "bubbles up error response", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth_access_token_request(bypass)
      expect_oauth_user_request(bypass, %{error: "Unknown error"}, status_code: 500)

      assert {:error, %RequestError{} = error} = OAuth.callback(config, params)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error\" => \"Unknown error\"}"
    end
  end

  describe "request/6 as GET request" do
    setup do
      {:ok, token: %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}}
    end

    test "with missing `:site` config", %{config: config, token: token} do
      config = Keyword.delete(config, :site)

      assert OAuth.request(config, token, :get, "/info") == {:error, %MissingKeyError{message: "Key `:site` not found in config"}}
    end

    test "with missing `:consumer_key` config", %{config: config, token: token} do
      config = Keyword.delete(config, :consumer_key)

      assert OAuth.request(config, token, :get, "/info") == {:error, %MissingKeyError{message: "Key `:consumer_key` not found in config"}}
    end

    test "with missing `:consumer_secret` config", %{config: config, token: token} do
      config = Keyword.delete(config, :consumer_secret)

      assert OAuth.request(config, token, :get, "/info") == {:error, %MissingKeyError{message: "Key `:consumer_secret` not found in config"}}
    end

    test "with missing `oauth_token` in token", %{config: config, token: token} do
      assert OAuth.request(config, Map.delete(token, "oauth_token"), :get, "/info") == {:error, "No `oauth_token` in token map"}
    end

    test "with missing `oauth_token_secret` in token", %{config: config, token: token} do
      assert OAuth.request(config, Map.delete(token, "oauth_token_secret"), :get, "/info") == {:error, "No `oauth_token_secret` in token map"}
    end

    test "gets", %{config: config, token: token, bypass: bypass} do
      expect_oauth_api_request(bypass, "/info", %{"success" => true})

      assert {:ok, response} = OAuth.request(config, token, :get, "/info")
      assert response.body == %{"success" => true}

      expect_oauth_api_request(bypass, "/info", %{"success" => true}, [params: [a: 1]], fn conn ->
        assert conn.params["a"] == "1"
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info", a: 1)
      assert response.body == %{"success" => true}

      expect_oauth_api_request(bypass, "/info", %{"success" => true}, [params: [a: 1]], fn conn ->
        assert Plug.Conn.get_req_header(conn, "b") == ["2"]
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info", [a: 1], [{"b", "2"}])
      assert response.body == %{"success" => true}
    end
  end

  test "request/6 as POST request", %{config: config, bypass: bypass} do
    token = %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}

    expect_oauth_api_request(bypass, "/info", %{"success" => true}, [], nil, "POST")

    assert {:ok, response} = OAuth.request(config, token, :post, "/info")
    assert response.body == %{"success" => true}

    expect_oauth_api_request(bypass, "/info", %{"success" => true}, [params: [a: 1]], fn conn ->
      {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
      params = URI.decode_query(body)

      assert params["a"] == "1"
    end, "POST")

    assert {:ok, response} = OAuth.request(config, token, :post, "/info", [a: 1])
    assert response.body == %{"success" => true}
  end
end
