defmodule Assent.Strategy.OAuth do
  @moduledoc """
  OAuth 1.0a strategy.

  `authorize_url/1` returns a map with a `:session_params` and `:url` key. The
  `:session_params` key carries a `:oauth_token_secret` value for the request.

  ## Configuration

    - `:consumer_key` - The OAuth consumer key, required
    - `:base_url` - The base URL of the OAuth server, required
    - `:signature_method` -  The signature method, optional, defaults to
      `:hmac_sha1`. The value may be one of the following:

      - `:hmac_sha1` - Generates signature with HMAC-SHA1
      - `:rsa_sha1` - Generates signature with RSA-SHA1
      - `:plaintext` - Doesn't generate signature
    - `:consumer_secret` - The OAuth consumer secret, required if
      `:signature_method` is either `:hmac_sha1` or `:plaintext`
    - `:private_key_path` - The path for the private key, required if
      `:signature_method` is `:rsa_sha1` and `:private_key` hasn't been set
    - `:private_key` - The private key content that can be defined instead of
      `:private_key_path`, required if `:signature_method` is `:rsa_sha1` and
      `:private_key_path` hasn't been set

  ## Usage

      config = [
        consumer_key: "REPLACE_WITH_CONSUMER_KEY",
        consumer_secret: "REPLACE_WITH_CONSUMER_SECRET",
        base_url: "https://auth.example.com",
        authorization_params: [scope: "user:read user:write"],
        user_url: "https://example.com/api/user"
      ]

      {:ok, {url: url, session_params: session_params}} =
        config
        |> Keyword.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> OAuth.authorize_url()

      {:ok, %{user: user, token: token}} =
        config
        |> Keyword.put(:session_params, session_params)
        |> OAuth.callback(params)
  """
  @behaviour Assent.Strategy

  alias Assent.Strategy, as: Helpers

  alias Assent.{
    Config,
    HTTPAdapter.HTTPResponse,
    InvalidResponseError,
    JWTAdapter,
    RequestError,
    UnexpectedResponseError
  }

  @type session_params :: %{
          oauth_token_secret: binary()
        }

  @type on_authorize_url ::
          {:ok, %{session_params: session_params(), url: binary()}} | {:error, term()}
  @type on_callback :: {:ok, %{user: map(), token: map()}} | {:error, term()}

  @doc """
  Generate authorization URL for request phase.

  ## Options

    - `:redirect_uri` - The URI that the server redirects the user to after
      authentication, required
    - `:request_token_url` - The path or URL to fetch the token from, optional,
      defaults to `/oauth/request_token`
    - `:authorize_url` - The path or URL for the OAuth server to redirect users
      to, defaults to `/oauth/authenticate`
    - `:authorization_params` - The authorization parameters, defaults to `[]`
  """
  @impl true
  @spec authorize_url(Keyword.t()) :: on_authorize_url()
  def authorize_url(config) do
    with {:ok, redirect_uri} <- Assent.fetch_config(config, :redirect_uri),
         {:ok, token} <- fetch_request_token(config, [{"oauth_callback", redirect_uri}]),
         {:ok, url, oauth_token_secret} <- gen_authorize_url(config, token) do
      {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}}
    end
  end

  defp fetch_request_token(config, oauth_params) do
    with {:ok, base_url} <- Config.__base_url__(config) do
      request_token_url = Keyword.get(config, :request_token_url, "/request_token")
      url = process_url(base_url, request_token_url)

      config
      |> do_request(:post, base_url, url, [], oauth_params)
      |> process_token_response()
    end
  end

  defp process_url(base_url, url) do
    case String.downcase(url) do
      <<"http://"::utf8, _::binary>> -> url
      <<"https://"::utf8, _::binary>> -> url
      _ -> base_url <> url
    end
  end

  defp do_request(
         config,
         method,
         base_url,
         url,
         params,
         oauth_params,
         headers \\ [],
         token_secret \\ nil
       ) do
    params =
      params
      |> Enum.to_list()
      |> Enum.map(fn {key, value} -> {to_string(key), value} end)

    signature_method = Keyword.get(config, :signature_method, :hmac_sha1)

    with {:ok, oauth_params} <- gen_oauth_params(config, signature_method, oauth_params),
         {:ok, signed_header} <-
           signed_header(
             config,
             signature_method,
             method,
             url,
             oauth_params,
             params,
             token_secret
           ) do
      req_headers = request_headers(method, [signed_header] ++ headers)
      req_body = request_body(method, params)
      query_params = url_params(method, params)
      url = Helpers.to_url(base_url, url, query_params)

      Helpers.http_request(method, url, req_body, req_headers, config)
    end
  end

  defp gen_oauth_params(config, signature_method, oauth_params) do
    with {:ok, consumer_key} <- Assent.fetch_config(config, :consumer_key) do
      nonce = gen_nonce()
      signature_method = signature_method_value(signature_method)
      timestamp = to_string(:os.system_time(:second))

      params =
        [
          {"oauth_consumer_key", consumer_key},
          {"oauth_nonce", nonce},
          {"oauth_signature_method", signature_method},
          {"oauth_timestamp", timestamp},
          {"oauth_version", "1.0"}
          | oauth_params
        ]

      {:ok, params}
    end
  end

  defp gen_nonce do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.encode64(padding: false)
  end

  defp signature_method_value(:hmac_sha1), do: "HMAC-SHA1"
  defp signature_method_value(:rsa_sha1), do: "RSA-SHA1"
  defp signature_method_value(:plaintext), do: "PLAINTEXT"

  defp signed_header(config, signature_method, method, url, oauth_params, params, token_secret) do
    uri = URI.parse(url)
    query_params = Map.to_list(URI.decode_query(uri.query || ""))
    request_params = params ++ query_params ++ oauth_params

    with {:ok, signature} <-
           gen_signature(config, method, uri, request_params, signature_method, token_secret) do
      oauth_header_value =
        Enum.map_join([{"oauth_signature", signature} | oauth_params], ", ", fn {key, value} ->
          percent_encode(key) <> "=\"" <> percent_encode(value) <> "\""
        end)

      {:ok, {"Authorization", "OAuth " <> oauth_header_value}}
    end
  end

  defp gen_signature(config, method, uri, request_params, :hmac_sha1, token_secret) do
    with {:ok, shared_secret} <- encoded_shared_secret(config, token_secret) do
      signature_base = encode_signature_base(method, uri, request_params)

      signature =
        :hmac
        |> :crypto.mac(:sha, shared_secret, signature_base)
        |> Base.encode64()

      {:ok, signature}
    end
  end

  defp gen_signature(config, method, uri, request_params, :rsa_sha1, _token_secret) do
    with {:ok, pem} <- JWTAdapter.load_private_key(config),
         {:ok, private_key} <- decode_pem(pem) do
      signature =
        method
        |> encode_signature_base(uri, request_params)
        |> :public_key.sign(:sha, private_key)
        |> Base.encode64()

      {:ok, signature}
    end
  end

  defp gen_signature(config, _method, _url, _request_params, :plaintext, token_secret),
    do: encoded_shared_secret(config, token_secret)

  defp encoded_shared_secret(config, token_secret) do
    with {:ok, consumer_secret} <- Assent.fetch_config(config, :consumer_secret) do
      shared_secret = Enum.map_join([consumer_secret, token_secret || ""], "&", &percent_encode/1)

      {:ok, shared_secret}
    end
  end

  defp percent_encode(value) do
    value
    |> to_string()
    |> URI.encode(&URI.char_unreserved?/1)
  end

  defp encode_signature_base(method, uri, request_params) do
    method =
      method
      |> to_string()
      |> String.upcase()

    base_string_uri =
      %{uri | query: nil, host: uri.host}
      |> URI.to_string()
      |> String.downcase()

    normalized_request_params =
      request_params
      |> Enum.map(fn {key, value} ->
        percent_encode(key) <> "=" <> percent_encode(value)
      end)
      |> Enum.sort()
      |> Enum.join("&")

    Enum.map_join([method, base_string_uri, normalized_request_params], "&", &percent_encode/1)
  end

  defp decode_pem(pem) do
    case :public_key.pem_decode(pem) do
      [entry] -> {:ok, :public_key.pem_entry_decode(entry)}
      _any -> {:error, "Private key should only have one entry"}
    end
  end

  defp request_headers(:post, headers),
    do: [{"content-type", "application/x-www-form-urlencoded"}] ++ headers

  defp request_headers(_method, headers), do: headers

  defp request_body(:post, req_params), do: URI.encode_query(req_params)
  defp request_body(_method, _req_params), do: nil

  defp url_params(:post, _params), do: []
  defp url_params(_method, params), do: params

  defp process_token_response({:ok, %HTTPResponse{status: 200, body: body} = response})
       when is_binary(body) do
    process_token_response({:ok, %{response | body: URI.decode_query(body)}})
  end

  defp process_token_response(
         {:ok,
          %HTTPResponse{
            status: 200,
            body: %{"oauth_token" => _, "oauth_token_secret" => _} = token
          }}
       ) do
    {:ok, token}
  end

  defp process_token_response(any), do: process_response(any)

  defp process_response({:ok, %HTTPResponse{} = response}),
    do: {:error, UnexpectedResponseError.exception(response: response)}

  defp process_response({:error, %HTTPResponse{} = response}),
    do: {:error, InvalidResponseError.exception(response: response)}

  defp process_response({:error, error}), do: {:error, error}

  defp gen_authorize_url(config, token) do
    with {:ok, base_url} <- Config.__base_url__(config),
         {:ok, oauth_token} <- fetch_from_token(token, "oauth_token"),
         {:ok, oauth_token_secret} <- fetch_from_token(token, "oauth_token_secret") do
      authorization_url = Keyword.get(config, :authorize_url, "/authorize")
      params = authorization_params(config, oauth_token: oauth_token)
      url = Helpers.to_url(base_url, authorization_url, params)

      {:ok, url, oauth_token_secret}
    end
  end

  defp fetch_from_token(token, key) do
    case Map.fetch(token, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, "No `#{key}` in token map"}
    end
  end

  defp authorization_params(config, params) do
    config
    |> Keyword.get(:authorization_params, [])
    |> Keyword.merge(params)
    |> List.keysort(0)
  end

  @doc """
  Callback phase for generating access token and fetch user data.

  ## Options

    - `:access_token_url` - The path or URL to fetch the access token from,
      optional, defaults to `/oauth/access_token`
    - `:user_url` - The path or URL to fetch user data, required
    - `:session_params` - The session parameters that was returned from
      `authorize_url/1`, optional
  """
  @impl true
  @spec callback(Keyword.t(), map(), atom()) :: on_callback()
  def callback(config, params, strategy \\ __MODULE__) do
    with {:ok, oauth_token} <- Assent.fetch_param(params, "oauth_token"),
         {:ok, oauth_verifier} <- Assent.fetch_param(params, "oauth_verifier"),
         {:ok, token} <- fetch_access_token(config, oauth_token, oauth_verifier),
         {:ok, user} <- strategy.fetch_user(config, token) do
      {:ok, %{user: user, token: token}}
    end
  end

  defp fetch_access_token(config, oauth_token, oauth_verifier) do
    with {:ok, base_url} <- Config.__base_url__(config) do
      access_token_url = Keyword.get(config, :access_token_url, "/access_token")
      url = process_url(base_url, access_token_url)
      oauth_token_secret = Kernel.get_in(config, [:session_params, :oauth_token_secret])

      config
      |> do_request(
        :post,
        base_url,
        url,
        [],
        [{"oauth_token", oauth_token}, {"oauth_verifier", oauth_verifier}],
        [],
        oauth_token_secret
      )
      |> process_token_response()
    end
  end

  @doc """
  Performs a signed HTTP request to the API using the oauth token.
  """
  @spec request(Keyword.t(), map(), atom(), binary(), map() | Keyword.t(), [{binary(), binary()}]) ::
          {:ok, map()} | {:error, term()}
  def request(config, token, method, url, params \\ [], headers \\ []) do
    with {:ok, base_url} <- Config.__base_url__(config),
         {:ok, oauth_token} <- fetch_from_token(token, "oauth_token"),
         {:ok, oauth_token_secret} <- fetch_from_token(token, "oauth_token_secret") do
      url = process_url(base_url, url)

      do_request(
        config,
        method,
        base_url,
        url,
        params,
        [{"oauth_token", oauth_token}],
        headers,
        oauth_token_secret
      )
    end
  end

  @doc false
  @spec fetch_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}
  def fetch_user(config, token) do
    with {:ok, url} <- Assent.fetch_config(config, :user_url) do
      case request(config, token, :get, url) do
        {:ok, %HTTPResponse{status: 200, body: user}} when is_map(user) ->
          {:ok, user}

        {:error, %HTTPResponse{status: 401} = response} ->
          {:error, RequestError.exception(message: "Unauthorized token", response: response)}

        other ->
          process_response(other)
      end
    end
  end
end
