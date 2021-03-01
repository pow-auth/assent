defmodule Assent.Strategy.OAuthTest do
  use Assent.Test.OAuthTestCase

  alias Assent.{Config.MissingKeyError, MissingParamError, RequestError, Strategy.OAuth}

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

  describe "authorize_url/2" do
    test "with missing `:redirect_uri` config", %{config: config} do
      config = Keyword.delete(config, :redirect_uri)

      assert OAuth.authorize_url(config) == {:error, %MissingKeyError{message: "Key `:redirect_uri` not found in config"}}
    end

    test "with missing `:site` config", %{config: config} do
      config = Keyword.delete(config, :site)

      assert OAuth.authorize_url(config) == {:error, %MissingKeyError{message: "Key `:site` not found in config"}}
    end

    test "with missing `:consumer_key` config", %{config: config} do
      config = Keyword.delete(config, :consumer_key)

      assert OAuth.authorize_url(config) == {:error, %MissingKeyError{message: "Key `:consumer_key` not found in config"}}
    end

    test "with missing `:consumer_secret` config", %{config: config} do
      config = Keyword.delete(config, :consumer_secret)

      assert OAuth.authorize_url(config) == {:error, %MissingKeyError{message: "Key `:consumer_secret` not found in config"}}
    end

    test "with unexpected succesful response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, params: %{"error_code" => 215, "error_message" => "Bad Authentication data."})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:"
      assert error.message =~ "%{\"error_code\" => \"215\", \"error_message\" => \"Bad Authentication data.\"}"
    end

    test "with error response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, status_code: 500, params: %{"error_code" => 215, "error_message" => "Bad Authentication data."})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error_code\" => \"215\", \"error_message\" => \"Bad Authentication data.\"}"
    end

    test "with json error response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, status_code: 500, content_type: "application/json", params: %{"errors" => [%{"code" => 215, "message" => "Bad Authentication data."}]})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"errors\" => [%{\"code\" => 215, \"message\" => \"Bad Authentication data.\"}]}"
    end

    test "with missing `oauth_token` in access token response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, params: %{oauth_token_secret: "hdhd0244k9j7ao03"})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:\n\n%{\"oauth_token_secret\" => \"hdhd0244k9j7ao03\"}\n"
    end

    test "with missing `oauth_token_secret` in access token response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, params: %{oauth_token: "hh5s93j4hdidpola"})

      assert {:error, %RequestError{} = error} = OAuth.authorize_url(config)
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:\n\n%{\"oauth_token\" => \"hh5s93j4hdidpola\"}\n"
    end

    test "returns url", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, [], fn _conn, oauth_params ->
        signature_base_string = gen_signature_base_string("POST&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Frequest_token&", oauth_params)

        assert oauth_params["oauth_callback"] == "http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback"
        assert oauth_params["oauth_consumer_key"] == config[:consumer_key]
        assert oauth_params["oauth_nonce"]
        assert signature = oauth_params["oauth_signature"]
        assert oauth_params["oauth_signature_method"] == "HMAC-SHA1"
        assert timestamp = oauth_params["oauth_timestamp"]
        assert oauth_params["oauth_version"] == "1.0"

        assert {:ok, decoded_signature} = Base.decode64(URI.decode(signature))
        assert :crypto.mac(:hmac, :sha, "#{config[:consumer_secret]}&", signature_base_string) == decoded_signature
        assert String.to_integer(timestamp) <= DateTime.to_unix(DateTime.utc_now())
      end)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: "hdhd0244k9j7ao03"}}} = OAuth.authorize_url(config)
      assert url == "http://localhost:#{bypass.port}/authorize?oauth_token=hh5s93j4hdidpola"
    end

    test "parses URI query params in `:request_token_url` for the signature", %{config: config, bypass: bypass} do
      config = Keyword.put(config, :request_token_url, "/request_token?a=1&c=3&b=2")

      expect_oauth_request_token_request(bypass, [], fn conn, oauth_params ->
        signature_base_string = gen_signature_base_string("POST&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Frequest_token&", Map.merge(oauth_params, conn.query_params))

        assert conn.query_params == %{"a" => "1", "b" => "2", "c" => "3"}
        assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
        assert :crypto.mac(:hmac, :sha, "#{config[:consumer_secret]}&", signature_base_string) == decoded_signature
      end)

      assert {:ok, _res} = OAuth.authorize_url(config)
    end

    test "parses URI query response with authorization params", %{config: config, bypass: bypass} do
      authorization_params = [scope: "reading writing", another_param: "param"]
      config = Keyword.put(config, :authorization_params, authorization_params)
      expect_oauth_request_token_request(bypass)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: _oauth_token_secret}}} = OAuth.authorize_url(config)
      assert url == "http://localhost:#{bypass.port}/authorize?another_param=param&oauth_token=hh5s93j4hdidpola&scope=reading+writing"
    end

    test "parses URI query response", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, content_type: "text/html", params: URI.encode_query(%{oauth_token: "encoded_uri_request_token", oauth_token_secret: "encoded_uri_token_secret"}))

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: "encoded_uri_token_secret"}}} = OAuth.authorize_url(config)
      assert url == "http://localhost:#{bypass.port}/authorize?oauth_token=encoded_uri_request_token"
    end
  end

  defp gen_signature_base_string(method_uri, params) do
    encoded_normalized_params =
      params
      |> Enum.reject(&elem(&1, 0) in ["oauth_signature"])
      |> Enum.map(fn {key, value} ->
        key <> "=" <> value
      end)
      |> Enum.sort()
      |> Enum.join("&")
      |> URI.encode(&URI.char_unreserved?/1)

    method_uri <> encoded_normalized_params
  end

  describe "authorize_url/2 with RSA-SHA1 signature method" do
    setup %{config: config} do
      config =
        config
        |> Keyword.put(:signature_method, :rsa_sha1)
        |> Keyword.put(:private_key, @private_key)
        |> Keyword.delete(:consumer_secret)

      {:ok, config: config}
    end

    test "with missing `:private_key` config", %{config: config} do
      config = Keyword.delete(config, :private_key)

      assert OAuth.authorize_url(config) == {:error, %MissingKeyError{message: "Key `:private_key` not found in config"}}
    end

    test "returns url", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, [], fn _conn, oauth_params ->
        decoded_public_key =
          @public_key
          |> :public_key.pem_decode()
          |> List.first()
          |> :public_key.pem_entry_decode()

        signature_base_string = gen_signature_base_string("POST&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Frequest_token&", oauth_params)

        assert oauth_params["oauth_signature_method"] == "RSA-SHA1"
        assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
        assert :public_key.verify(signature_base_string, :sha, decoded_signature, decoded_public_key)
      end)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: "hdhd0244k9j7ao03"}}} = OAuth.authorize_url(config)
      assert url == "http://localhost:#{bypass.port}/authorize?oauth_token=hh5s93j4hdidpola"
    end

    test "with `:private_key_path` config", %{config: config, bypass: bypass} do
      File.mkdir("tmp/")
      File.write!("tmp/private-key.pem", @private_key)

      config =
        config
        |> Keyword.delete(:private_key)
        |> Keyword.put(:private_key_path, "tmp/private-key.pem")

      expect_oauth_request_token_request(bypass)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}} = OAuth.authorize_url(config)
      refute is_nil(oauth_token_secret)
      assert url == "http://localhost:#{bypass.port}/authorize?oauth_token=hh5s93j4hdidpola"
    end
  end

  describe "authorize_url/2 with PLAINTEXT signature method" do
    setup %{config: config} do
      config = Keyword.put(config, :signature_method, :plaintext)

      {:ok, config: config}
    end

    test "with missing `:consumer_secret` config", %{config: config} do
      config = Keyword.delete(config, :consumer_secret)

      assert OAuth.authorize_url(config) == {:error, %MissingKeyError{message: "Key `:consumer_secret` not found in config"}}
    end

    test "returns url", %{config: config, bypass: bypass} do
      expect_oauth_request_token_request(bypass, [], fn _conn, oauth_params ->
        assert oauth_params["oauth_signature_method"] == "PLAINTEXT"
        assert oauth_params["oauth_signature"] == URI.encode("#{config[:consumer_secret]}&", &URI.char_unreserved?/1)
      end)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}} = OAuth.authorize_url(config)
      refute is_nil(oauth_token_secret)
      assert url == "http://localhost:#{bypass.port}/authorize?oauth_token=hh5s93j4hdidpola"
    end
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :user_url, "/api/user")

      {:ok, config: config}
    end

    test "with missing oauth_token param", %{config: config, callback_params: params} do
      params = Map.delete(params, "oauth_token")

      assert {:error, %MissingParamError{} = error} = OAuth.callback(config, params)
      assert error.message == "Expected \"oauth_token\" to exist in params, but only found the following keys: [\"oauth_verifier\"]"
      assert error.params == %{"oauth_verifier" => "hfdp7dh39dks9884"}
    end

    test "with missing oauth_verifier param", %{config: config, callback_params: params} do
      params = Map.delete(params, "oauth_verifier")

      assert {:error, %MissingParamError{} = error} = OAuth.callback(config, params)
      assert error.message == "Expected \"oauth_verifier\" to exist in params, but only found the following keys: [\"oauth_token\"]"
      assert error.params == %{"oauth_token" => "hh5s93j4hdidpola"}
    end

    test "with missing `:site` config", %{config: config, callback_params: callback_params} do
      config = Keyword.delete(config, :site)

      assert OAuth.callback(config, callback_params) == {:error, %MissingKeyError{message: "Key `:site` not found in config"}}
    end

    test "bubbles up access token error response", %{config: config, callback_params: callback_params, bypass: bypass} do
      expect_oauth_access_token_request(bypass, status_code: 500, params: %{error: "Unknown error"})

      assert {:error, %RequestError{} = error} = OAuth.callback(config, callback_params)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error\" => \"Unknown error\"}"
    end

    test "with missing `oauth_token` in access token response", %{config: config, callback_params: callback_params, bypass: bypass} do
      expect_oauth_access_token_request(bypass, params: %{oauth_token_secret: "token_secret"})

      assert {:error, %RequestError{} = error} = OAuth.callback(config, callback_params)
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:\n\n%{\"oauth_token_secret\" => \"token_secret\"}\n"
    end

    test "with missing `oauth_token_secret` in access token response", %{config: config, callback_params: callback_params, bypass: bypass} do
      expect_oauth_access_token_request(bypass, params: %{oauth_token: "token"})

      assert {:error, %RequestError{} = error} = OAuth.callback(config, callback_params)
      assert error.error == :unexpected_response
      assert error.message =~ "An unexpected success response was received:\n\n%{\"oauth_token\" => \"token\"}\n"
    end

    test "bubbles up user request error response", %{config: config, callback_params: callback_params, bypass: bypass} do
      expect_oauth_access_token_request(bypass)
      expect_oauth_user_request(bypass, %{error: "Unknown error"}, status_code: 500)

      assert {:error, %RequestError{} = error} = OAuth.callback(config, callback_params)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 500"
      assert error.message =~ "%{\"error\" => \"Unknown error\"}"
    end

    test "normalizes data", %{config: config, callback_params: callback_params, bypass: bypass} do
      expect_oauth_access_token_request(bypass, [], fn _conn, oauth_params ->
        signature_base_string = gen_signature_base_string("POST&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Faccess_token&", oauth_params)

        assert oauth_params["oauth_consumer_key"] == config[:consumer_key]
        assert signature = oauth_params["oauth_signature"]
        assert oauth_params["oauth_signature_method"] == "HMAC-SHA1"
        assert oauth_params["oauth_token"] == callback_params["oauth_token"]
        assert oauth_params["oauth_verifier"] == callback_params["oauth_verifier"]

        assert {:ok, decoded_signature} = Base.decode64(URI.decode(signature))
        assert :crypto.mac(:hmac, :sha, "#{config[:consumer_secret]}&#{config[:session_params][:oauth_token_secret]}", signature_base_string) == decoded_signature
      end)

      expect_oauth_user_request(bypass, %{email: nil})

      assert {:ok, %{user: user, token: token}} = OAuth.callback(config, callback_params)
      assert user == %{"email" => nil}
      assert token == %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}
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

    test "with missing `oauth_token` in token", %{config: config, token: token} do
      assert OAuth.request(config, Map.delete(token, "oauth_token"), :get, "/info") == {:error, "No `oauth_token` in token map"}
    end

    test "with missing `oauth_token_secret` in token", %{config: config, token: token} do
      assert OAuth.request(config, Map.delete(token, "oauth_token_secret"), :get, "/info") == {:error, "No `oauth_token_secret` in token map"}
    end

    test "with missing `:consumer_key` config", %{config: config, token: token} do
      config = Keyword.delete(config, :consumer_key)

      assert OAuth.request(config, token, :get, "/info") == {:error, %MissingKeyError{message: "Key `:consumer_key` not found in config"}}
    end

    test "with missing `:consumer_secret` config", %{config: config, token: token} do
      config = Keyword.delete(config, :consumer_secret)

      assert OAuth.request(config, token, :get, "/info") == {:error, %MissingKeyError{message: "Key `:consumer_secret` not found in config"}}
    end

    test "with network error", %{config: config, token: token, bypass: bypass} do
      Bypass.down(bypass)

      assert {:error, %Assent.RequestError{} = error} = OAuth.request(config, token, :get, "/info")
      assert error.error == :unreachable
      assert error.message =~ "Server was unreachable with Assent.HTTPAdapter.Httpc."
      assert error.message =~ "{:failed_connect, "
      assert error.message =~ "URL: http://localhost:#{bypass.port}/info"
    end

    test "fetches", %{config: config, token: token, bypass: bypass} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"

      expect_oauth_api_request(bypass, "/info", %{"success" => true}, [], fn _conn, oauth_params ->
        signature_base_string = gen_signature_base_string("GET&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Finfo&", oauth_params)

        assert oauth_params["oauth_consumer_key"] == config[:consumer_key]
        assert oauth_params["oauth_nonce"]
        assert signature = oauth_params["oauth_signature"]
        assert oauth_params["oauth_signature_method"] == "HMAC-SHA1"
        assert timestamp = oauth_params["oauth_timestamp"]
        assert oauth_params["oauth_version"] == "1.0"

        assert {:ok, decoded_signature} = Base.decode64(URI.decode(signature))
        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
        assert String.to_integer(timestamp) <= DateTime.to_unix(DateTime.utc_now())
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info")
      assert response.body == %{"success" => true}
    end

    test "with params", %{config: config, token: token, bypass: bypass} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"

      expect_oauth_api_request(bypass, "/info", %{"success" => true}, [params: [a: 1]], fn conn, oauth_params ->
        signature_base_string = gen_signature_base_string("GET&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Finfo&", Map.merge(oauth_params, conn.params))

        assert conn.params["a"] == "1"
        assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info", a: 1)
      assert response.body == %{"success" => true}
    end

    test "with params and request header", %{config: config, token: token, bypass: bypass} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"

      expect_oauth_api_request(bypass, "/info", %{"success" => true}, [params: [a: 1]], fn conn, oauth_params ->
        signature_base_string = gen_signature_base_string("GET&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Finfo&", Map.merge(oauth_params, conn.params))

        assert Plug.Conn.get_req_header(conn, "b") == ["2"]
        assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info", [a: 1], [{"b", "2"}])
      assert response.body == %{"success" => true}
    end

    test "with uppercase url", %{config: config, token: token, bypass: bypass} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"
      config        = Keyword.put(config, :site, String.upcase(config[:site]))

      expect_oauth_api_request(bypass, "/INFO", %{"success" => true}, [], fn _conn, oauth_params ->
        signature_base_string = gen_signature_base_string("GET&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Finfo&", oauth_params)

        assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/INFO")
      assert response.body == %{"success" => true}
    end

    test "with RSA-SHA1 signature method", %{config: config, token: token, bypass: bypass} do
      config =
        config
        |> Keyword.put(:signature_method, :rsa_sha1)
        |> Keyword.put(:private_key, @private_key)
        |> Keyword.delete(:consumer_secret)

      expect_oauth_api_request(bypass, "/info", %{"success" => true}, [], fn _conn, oauth_params ->
        decoded_public_key =
          @public_key
          |> :public_key.pem_decode()
          |> List.first()
          |> :public_key.pem_entry_decode()

        signature_base_string = gen_signature_base_string("GET&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Finfo&", oauth_params)

        assert oauth_params["oauth_signature_method"] == "RSA-SHA1"
        assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
        assert :public_key.verify(signature_base_string, :sha, decoded_signature, decoded_public_key)
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info")
      assert response.body == %{"success" => true}
    end

    test "with PLAINTEXT signature method", %{config: config, token: token, bypass: bypass} do
      config = Keyword.put(config, :signature_method, :plaintext)

      expect_oauth_api_request(bypass, "/info", %{"success" => true}, [], fn _conn, oauth_params ->
        assert oauth_params["oauth_signature_method"] == "PLAINTEXT"
        assert oauth_params["oauth_signature"] == URI.encode("#{config[:consumer_secret]}&#{token["oauth_token_secret"]}", &URI.char_unreserved?/1)
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info")
      assert response.body == %{"success" => true}
    end
  end

  test "request/6 as POST request", %{config: config, bypass: bypass} do
    token = %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}
    shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"

    expect_oauth_api_request(bypass, "/info", %{"success" => true}, [], fn _conn, oauth_params ->
      signature_base_string = gen_signature_base_string("POST&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Finfo&", oauth_params)

      assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
      assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
    end, "POST")

    assert {:ok, response} = OAuth.request(config, token, :post, "/info")
    assert response.body == %{"success" => true}

    expect_oauth_api_request(bypass, "/info", %{"success" => true}, [params: [a: 1]], fn conn, oauth_params ->
      {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
      params = URI.decode_query(body)
      signature_base_string = gen_signature_base_string("POST&http%3A%2F%2Flocalhost%3A#{bypass.port}%2Finfo&", Map.merge(oauth_params, params))

      assert params == %{"a" => "1"}
      assert {:ok, decoded_signature} = Base.decode64(URI.decode(oauth_params["oauth_signature"]))
      assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
    end, "POST")

    assert {:ok, response} = OAuth.request(config, token, :post, "/info", [a: 1])
    assert response.body == %{"success" => true}
  end
end
