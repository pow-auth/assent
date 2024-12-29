defmodule Assent.Strategy.OAuthTest do
  use Assent.Test.OAuthTestCase

  alias Assent.UnexpectedResponseError

  alias Assent.{
    Config.MissingKeyError,
    InvalidResponseError,
    MissingParamError,
    RequestError,
    ServerUnreachableError,
    Strategy.OAuth
  }

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

      assert {:error, %MissingKeyError{} = error} = OAuth.authorize_url(config)
      assert error.key == :redirect_uri
    end

    test "with missing `:base_url` config", %{config: config} do
      config = Keyword.delete(config, :base_url)

      assert {:error, %MissingKeyError{} = error} = OAuth.authorize_url(config)
      assert error.key == :base_url
    end

    test "with missing `:consumer_key` config", %{config: config} do
      config = Keyword.delete(config, :consumer_key)

      assert {:error, %MissingKeyError{} = error} = OAuth.authorize_url(config)
      assert error.key == :consumer_key
    end

    test "with missing `:consumer_secret` config", %{config: config} do
      config = Keyword.delete(config, :consumer_secret)

      assert {:error, %MissingKeyError{} = error} = OAuth.authorize_url(config)
      assert error.key == :consumer_secret
    end

    test "with `:request_token_url` being unreachable", %{config: config} do
      request_token_url = TestServer.url("/request_token")
      TestServer.stop()

      assert {:error, %ServerUnreachableError{} = error} = OAuth.authorize_url(config)
      assert Exception.message(error) =~ "The server was unreachable."
      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request_url == request_token_url
      assert {:failed_connect, _} = error.reason
    end

    test "with `:request_token_url` returning unexpected success", %{config: config} do
      expect_oauth_request_token_request(
        params: %{"error_code" => 215, "error_message" => "Bad Authentication data."}
      )

      assert {:error, %UnexpectedResponseError{} = error} = OAuth.authorize_url(config)
      assert Exception.message(error) =~ "An unexpected response was received."
      assert error.response.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.response.request_url == TestServer.url("/request_token")
      assert error.response.status == 200

      assert error.response.body == %{
               "error_code" => "215",
               "error_message" => "Bad Authentication data."
             }
    end

    test "with `:request_token_url` returning HTTP error", %{config: config} do
      expect_oauth_request_token_request(
        status_code: 500,
        params: %{"error_code" => 215, "error_message" => "Bad Authentication data."}
      )

      assert {:error, %InvalidResponseError{} = error} = OAuth.authorize_url(config)
      assert Exception.message(error) =~ "An invalid response was received."
      assert error.response.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.response.request_url == TestServer.url("/request_token")
      assert error.response.status == 500

      assert error.response.body == %{
               "error_code" => "215",
               "error_message" => "Bad Authentication data."
             }
    end

    test "with `:request_token_url` returning missing `oauth_token`", %{config: config} do
      expect_oauth_request_token_request(params: %{oauth_token_secret: "hdhd0244k9j7ao03"})

      assert {:error, %UnexpectedResponseError{} = error} = OAuth.authorize_url(config)
      assert Exception.message(error) =~ "An unexpected response was received."
      assert error.response.body == %{"oauth_token_secret" => "hdhd0244k9j7ao03"}
    end

    test "with `:request_token_url` returning missing `oauth_token_secret`", %{config: config} do
      expect_oauth_request_token_request(params: %{oauth_token: "hh5s93j4hdidpola"})

      assert {:error, %UnexpectedResponseError{} = error} = OAuth.authorize_url(config)
      assert Exception.message(error) =~ "An unexpected response was received."
      assert error.response.body == %{"oauth_token" => "hh5s93j4hdidpola"}
    end

    test "returns url", %{config: config} do
      request_token_url = TestServer.url("/request_token")

      expect_oauth_request_token_request([], fn _conn, oauth_params ->
        signature_base_string =
          gen_signature_base_string(
            "POST&#{URI.encode_www_form(request_token_url)}&",
            oauth_params
          )

        assert oauth_params["oauth_callback"] == "http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback"
        assert oauth_params["oauth_consumer_key"] == config[:consumer_key]
        assert oauth_params["oauth_nonce"]
        assert signature = oauth_params["oauth_signature"]
        assert oauth_params["oauth_signature_method"] == "HMAC-SHA1"
        assert timestamp = oauth_params["oauth_timestamp"]
        assert oauth_params["oauth_version"] == "1.0"

        assert {:ok, decoded_signature} = Base.decode64(URI.decode(signature))

        assert :crypto.mac(:hmac, :sha, "#{config[:consumer_secret]}&", signature_base_string) ==
                 decoded_signature

        assert String.to_integer(timestamp) <= DateTime.to_unix(DateTime.utc_now())
      end)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: "hdhd0244k9j7ao03"}}} =
               OAuth.authorize_url(config)

      assert url == TestServer.url("/authorize?oauth_token=hh5s93j4hdidpola")
    end

    test "with `:request_token_url` URI query params", %{config: config} do
      config = Keyword.put(config, :request_token_url, "/request_token?a=1&c=3&b=2")
      request_token_url = TestServer.url("/request_token")

      expect_oauth_request_token_request([], fn conn, oauth_params ->
        signature_base_string =
          gen_signature_base_string(
            "POST&#{URI.encode_www_form(request_token_url)}&",
            Map.merge(oauth_params, conn.query_params)
          )

        assert conn.query_params == %{"a" => "1", "b" => "2", "c" => "3"}

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :crypto.mac(:hmac, :sha, "#{config[:consumer_secret]}&", signature_base_string) ==
                 decoded_signature
      end)

      assert {:ok, _res} = OAuth.authorize_url(config)
    end

    test "with `:authorization_params`", %{config: config} do
      authorization_params = [scope: "reading writing", another_param: "param"]
      config = Keyword.put(config, :authorization_params, authorization_params)
      expect_oauth_request_token_request()

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: _oauth_token_secret}}} =
               OAuth.authorize_url(config)

      assert url ==
               TestServer.url(
                 "/authorize?another_param=param&oauth_token=hh5s93j4hdidpola&scope=reading+writing"
               )
    end

    test "with `:request_token_url` returning URI query encoded response", %{config: config} do
      expect_oauth_request_token_request(
        content_type: "text/html",
        params:
          URI.encode_query(%{
            oauth_token: "encoded_uri_request_token",
            oauth_token_secret: "encoded_uri_token_secret"
          })
      )

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: "encoded_uri_token_secret"}}} =
               OAuth.authorize_url(config)

      assert url == TestServer.url("/authorize?oauth_token=encoded_uri_request_token")
    end
  end

  defp gen_signature_base_string(method_uri, params) do
    encoded_normalized_params =
      params
      |> Enum.reject(&(elem(&1, 0) in ["oauth_signature"]))
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

      assert {:error, %MissingKeyError{} = error} = OAuth.authorize_url(config)
      assert error.key == :private_key
    end

    test "returns url", %{config: config} do
      request_token_url = TestServer.url("/request_token")

      expect_oauth_request_token_request([], fn _conn, oauth_params ->
        decoded_public_key =
          @public_key
          |> :public_key.pem_decode()
          |> List.first()
          |> :public_key.pem_entry_decode()

        signature_base_string =
          gen_signature_base_string(
            "POST&#{URI.encode_www_form(request_token_url)}&",
            oauth_params
          )

        assert oauth_params["oauth_signature_method"] == "RSA-SHA1"

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :public_key.verify(
                 signature_base_string,
                 :sha,
                 decoded_signature,
                 decoded_public_key
               )
      end)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: "hdhd0244k9j7ao03"}}} =
               OAuth.authorize_url(config)

      assert url == TestServer.url("/authorize?oauth_token=hh5s93j4hdidpola")
    end

    test "with `:private_key_path` config", %{config: config} do
      File.mkdir_p!("tmp/")
      File.write!("tmp/private-key.pem", @private_key)

      config =
        config
        |> Keyword.delete(:private_key)
        |> Keyword.put(:private_key_path, "tmp/private-key.pem")

      expect_oauth_request_token_request()

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}} =
               OAuth.authorize_url(config)

      refute is_nil(oauth_token_secret)
      assert url == TestServer.url("/authorize?oauth_token=hh5s93j4hdidpola")
    end

    test "with `:private_key_path` config with missing file", %{config: config} do
      config =
        config
        |> Keyword.delete(:private_key)
        |> Keyword.put(:private_key_path, "tmp/missing.pem")

      assert {:error, "Failed to read \"tmp/missing.pem\", got; :enoent"} =
               OAuth.authorize_url(config)
    end
  end

  describe "authorize_url/2 with PLAINTEXT signature method" do
    setup %{config: config} do
      config = Keyword.put(config, :signature_method, :plaintext)

      {:ok, config: config}
    end

    test "with missing `:consumer_secret` config", %{config: config} do
      config = Keyword.delete(config, :consumer_secret)

      assert {:error, %MissingKeyError{} = error} = OAuth.authorize_url(config)
      assert error.key == :consumer_secret
    end

    test "returns url", %{config: config} do
      expect_oauth_request_token_request([], fn _conn, oauth_params ->
        assert oauth_params["oauth_signature_method"] == "PLAINTEXT"

        assert oauth_params["oauth_signature"] ==
                 URI.encode("#{config[:consumer_secret]}&", &URI.char_unreserved?/1)
      end)

      assert {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}} =
               OAuth.authorize_url(config)

      refute is_nil(oauth_token_secret)
      assert url == TestServer.url("/authorize?oauth_token=hh5s93j4hdidpola")
    end
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :user_url, "/api/user")

      {:ok, config: config}
    end

    test "with missing `oauth_token` param", %{config: config, callback_params: params} do
      params = Map.delete(params, "oauth_token")

      assert {:error, %MissingParamError{} = error} = OAuth.callback(config, params)

      assert Exception.message(error) ==
               "Expected \"oauth_token\" in params, got: [\"oauth_verifier\"]"

      assert error.expected_key == "oauth_token"
      assert error.params == %{"oauth_verifier" => "hfdp7dh39dks9884"}
    end

    test "with missing `oauth_verifier` param", %{config: config, callback_params: params} do
      params = Map.delete(params, "oauth_verifier")

      assert {:error, %MissingParamError{} = error} = OAuth.callback(config, params)

      assert Exception.message(error) ==
               "Expected \"oauth_verifier\" in params, got: [\"oauth_token\"]"

      assert error.expected_key == "oauth_verifier"
      assert error.params == %{"oauth_token" => "hh5s93j4hdidpola"}
    end

    test "with missing `:base_url` config", %{config: config, callback_params: callback_params} do
      config = Keyword.delete(config, :base_url)

      assert {:error, %MissingKeyError{} = error} = OAuth.callback(config, callback_params)
      assert error.key == :base_url
    end

    test "with `:access_token_url` being unreachable", %{
      config: config,
      callback_params: callback_params
    } do
      access_token_url = TestServer.url("/access_token")
      TestServer.stop()

      assert {:error, %ServerUnreachableError{} = error} = OAuth.callback(config, callback_params)
      assert Exception.message(error) =~ "The server was unreachable."
      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request_url == access_token_url
      assert {:failed_connect, _} = error.reason
    end

    test "with `:access_token_url` returning error", %{
      config: config,
      callback_params: callback_params
    } do
      expect_oauth_access_token_request(status_code: 500, params: %{error: "Unknown error"})

      assert {:error, %InvalidResponseError{} = error} = OAuth.callback(config, callback_params)
      assert Exception.message(error) =~ "Response status: 500"
      assert error.response.body == %{"error" => "Unknown error"}
    end

    test "with `:access_token_url` returning missing `oauth_token`", %{
      config: config,
      callback_params: callback_params
    } do
      expect_oauth_access_token_request(params: %{oauth_token_secret: "token_secret"})

      assert {:error, %UnexpectedResponseError{} = error} =
               OAuth.callback(config, callback_params)

      assert Exception.message(error) =~ "An unexpected response was received."
      assert error.response.body == %{"oauth_token_secret" => "token_secret"}
    end

    test "with `:access_token_url` returning missing `oauth_token_secret`", %{
      config: config,
      callback_params: callback_params
    } do
      expect_oauth_access_token_request(params: %{oauth_token: "token"})

      assert {:error, %UnexpectedResponseError{} = error} =
               OAuth.callback(config, callback_params)

      assert Exception.message(error) =~ "An unexpected response was received."
      assert error.response.body == %{"oauth_token" => "token"}
    end

    test "with missing `:user_url`", %{config: config, callback_params: params} do
      config = Keyword.delete(config, :user_url)

      expect_oauth_access_token_request()

      assert {:error, %MissingKeyError{} = error} = OAuth.callback(config, params)
      assert error.key == :user_url
    end

    test "with `:user_url` being unreachable", %{config: config, callback_params: params} do
      config = Keyword.put(config, :user_url, "http://localhost:8888/api/user")

      expect_oauth_access_token_request()

      assert {:error, %ServerUnreachableError{}} = OAuth.callback(config, params)
    end

    test "with `:user_url` returning HTTP unauthorized", %{
      config: config,
      callback_params: params
    } do
      expect_oauth_access_token_request()
      expect_oauth_user_request(%{"error" => "Unauthorized"}, status_code: 401)

      assert {:error, %RequestError{} = error} = OAuth.callback(config, params)
      assert error.message == "Unauthorized token"
      assert error.response.status == 401
      assert error.response.body == %{"error" => "Unauthorized"}
    end

    test "normalizes data", %{config: config, callback_params: callback_params} do
      access_token_url = TestServer.url("/access_token")

      expect_oauth_access_token_request([], fn _conn, oauth_params ->
        signature_base_string =
          gen_signature_base_string(
            "POST&#{URI.encode_www_form(access_token_url)}&",
            oauth_params
          )

        assert oauth_params["oauth_consumer_key"] == config[:consumer_key]
        assert signature = oauth_params["oauth_signature"]
        assert oauth_params["oauth_signature_method"] == "HMAC-SHA1"
        assert oauth_params["oauth_token"] == callback_params["oauth_token"]
        assert oauth_params["oauth_verifier"] == callback_params["oauth_verifier"]

        assert {:ok, decoded_signature} = Base.decode64(URI.decode(signature))

        assert :crypto.mac(
                 :hmac,
                 :sha,
                 "#{config[:consumer_secret]}&#{config[:session_params][:oauth_token_secret]}",
                 signature_base_string
               ) == decoded_signature
      end)

      expect_oauth_user_request(%{email: nil})

      assert {:ok, %{user: user, token: token}} = OAuth.callback(config, callback_params)
      assert user == %{"email" => nil}
      assert token == %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}
    end
  end

  describe "request/6 as GET request" do
    setup do
      {:ok, token: %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}}
    end

    test "with missing `:base_url` config", %{config: config, token: token} do
      config = Keyword.delete(config, :base_url)

      assert {:error, %MissingKeyError{} = error} = OAuth.request(config, token, :get, "/info")
      assert error.key == :base_url
    end

    test "with missing `oauth_token` in token", %{config: config, token: token} do
      assert OAuth.request(config, Map.delete(token, "oauth_token"), :get, "/info") ==
               {:error, "No `oauth_token` in token map"}
    end

    test "with missing `oauth_token_secret` in token", %{config: config, token: token} do
      assert OAuth.request(config, Map.delete(token, "oauth_token_secret"), :get, "/info") ==
               {:error, "No `oauth_token_secret` in token map"}
    end

    test "with missing `:consumer_key` config", %{config: config, token: token} do
      config = Keyword.delete(config, :consumer_key)

      assert {:error, %MissingKeyError{} = error} = OAuth.request(config, token, :get, "/info")
      assert error.key == :consumer_key
    end

    test "with missing `:consumer_secret` config", %{config: config, token: token} do
      config = Keyword.delete(config, :consumer_secret)

      assert {:error, %MissingKeyError{} = error} = OAuth.request(config, token, :get, "/info")
      assert error.key == :consumer_secret
    end

    test "with network error", %{config: config, token: token} do
      info_url = TestServer.url("/info")
      TestServer.stop()

      assert {:error, %ServerUnreachableError{} = error} =
               OAuth.request(config, token, :get, "/info")

      assert Exception.message(error) =~ "The server was unreachable."
      assert error.http_adapter == Assent.HTTPAdapter.Httpc
      assert error.request_url == info_url
      assert {:failed_connect, _} = error.reason
    end

    test "fetches", %{config: config, token: token} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"
      info_url = TestServer.url("/info")

      expect_oauth_api_request("/info", %{"success" => true}, [], fn _conn, oauth_params ->
        signature_base_string =
          gen_signature_base_string("GET&#{URI.encode_www_form(info_url)}&", oauth_params)

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

    test "with params", %{config: config, token: token} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"
      info_url = TestServer.url("/info")

      expect_oauth_api_request("/info", %{"success" => true}, [params: [a: 1]], fn conn,
                                                                                   oauth_params ->
        signature_base_string =
          gen_signature_base_string(
            "GET&#{URI.encode_www_form(info_url)}&",
            Map.merge(oauth_params, conn.params)
          )

        assert conn.params["a"] == "1"

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info", a: 1)
      assert response.body == %{"success" => true}
    end

    test "with params and request header", %{config: config, token: token} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"
      info_url = TestServer.url("/info")

      expect_oauth_api_request("/info", %{"success" => true}, [params: [a: 1]], fn conn,
                                                                                   oauth_params ->
        signature_base_string =
          gen_signature_base_string(
            "GET&#{URI.encode_www_form(info_url)}&",
            Map.merge(oauth_params, conn.params)
          )

        assert Plug.Conn.get_req_header(conn, "b") == ["2"]

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info", [a: 1], [{"b", "2"}])
      assert response.body == %{"success" => true}
    end

    test "with uppercase url", %{config: config, token: token} do
      shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"
      config = Keyword.put(config, :base_url, String.upcase(config[:base_url]))
      info_url = TestServer.url("/info")

      expect_oauth_api_request("/INFO", %{"success" => true}, [], fn _conn, oauth_params ->
        signature_base_string =
          gen_signature_base_string("GET&#{URI.encode_www_form(info_url)}&", oauth_params)

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/INFO")
      assert response.body == %{"success" => true}
    end

    test "with RSA-SHA1 signature method", %{config: config, token: token} do
      config =
        config
        |> Keyword.put(:signature_method, :rsa_sha1)
        |> Keyword.put(:private_key, @private_key)
        |> Keyword.delete(:consumer_secret)

      info_url = TestServer.url("/info")

      expect_oauth_api_request("/info", %{"success" => true}, [], fn _conn, oauth_params ->
        decoded_public_key =
          @public_key
          |> :public_key.pem_decode()
          |> List.first()
          |> :public_key.pem_entry_decode()

        signature_base_string =
          gen_signature_base_string("GET&#{URI.encode_www_form(info_url)}&", oauth_params)

        assert oauth_params["oauth_signature_method"] == "RSA-SHA1"

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :public_key.verify(
                 signature_base_string,
                 :sha,
                 decoded_signature,
                 decoded_public_key
               )
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info")
      assert response.body == %{"success" => true}
    end

    test "with PLAINTEXT signature method", %{config: config, token: token} do
      config = Keyword.put(config, :signature_method, :plaintext)

      expect_oauth_api_request("/info", %{"success" => true}, [], fn _conn, oauth_params ->
        assert oauth_params["oauth_signature_method"] == "PLAINTEXT"

        assert oauth_params["oauth_signature"] ==
                 URI.encode(
                   "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}",
                   &URI.char_unreserved?/1
                 )
      end)

      assert {:ok, response} = OAuth.request(config, token, :get, "/info")
      assert response.body == %{"success" => true}
    end
  end

  test "request/6 as POST request", %{config: config} do
    token = %{"oauth_token" => "token", "oauth_token_secret" => "token_secret"}
    shared_secret = "#{config[:consumer_secret]}&#{token["oauth_token_secret"]}"
    info_url = TestServer.url("/info")

    expect_oauth_api_request(
      "/info",
      %{"success" => true},
      [],
      fn _conn, oauth_params ->
        signature_base_string =
          gen_signature_base_string("POST&#{URI.encode_www_form(info_url)}&", oauth_params)

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end,
      "POST"
    )

    assert {:ok, response} = OAuth.request(config, token, :post, "/info")
    assert response.body == %{"success" => true}

    expect_oauth_api_request(
      "/info",
      %{"success" => true},
      [params: [a: 1]],
      fn conn, oauth_params ->
        {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        signature_base_string =
          gen_signature_base_string(
            "POST&#{URI.encode_www_form(info_url)}&",
            Map.merge(oauth_params, params)
          )

        assert params == %{"a" => "1"}

        assert {:ok, decoded_signature} =
                 Base.decode64(URI.decode(oauth_params["oauth_signature"]))

        assert :crypto.mac(:hmac, :sha, shared_secret, signature_base_string) == decoded_signature
      end,
      "POST"
    )

    assert {:ok, response} = OAuth.request(config, token, :post, "/info", a: 1)
    assert response.body == %{"success" => true}
  end
end
