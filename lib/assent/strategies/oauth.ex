defmodule Assent.Strategy.OAuth do
  @moduledoc """
  OAuth strategy.

  `authorize_url/1` returns a map with a `:session_params` and `:url` key. The
  `:session_params` key carries a `:oauth_token_secret` value for the request.

  ## Configuration

    - `:consumer_key` - The OAuth consumer key, required
    - `:consumer_secret` - The OAuth consumer secret, required
    - `:site` - The domain of the OAuth server, required

  ## Usage

      config = [
        consumer_key: "REPLACE_WITH_CONSUMER_KEY",
        consumer_secret: "REPLACE_WITH_CONSUMER_SECRET",
        site: "https://auth.example.com",
        authorization_params: [scope: "user:read user:write"],
        user_url: "https://example.com/api/user"
      ]

      {:ok, {url: url, session_params: session_params}} =
        config
        |> Assent.Config.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> OAuth.authorize_url()

      {:ok, %{user: user, token: token}} =
        config
        |> Assent.Config.put(:session_params, session_params)
        |> OAuth.callback(params)
  """
  @behaviour Assent.Strategy

  alias Assent.Strategy, as: Helpers
  alias Assent.{Config, HTTPAdapter.HTTPResponse, RequestError}

  @doc """
  Generate authorization URL for request phase.

  ## Configuration

    - `:redirect_uri` - The URI that the server redirects the user to after
      authentication, required
    - `:request_token_url` - The path or URL to fetch the token from, optional,
      defaults to `/oauth/request_token`
    - `:authorize_url` - The path or URL for the OAuth server to redirect users
      to, defaults to `/oauth/authenticate`
    - `:authorization_params` - The authorization parameters, defaults to `[]`
  """
  @impl true
  @spec authorize_url(Config.t()) :: {:ok, %{url: binary(), session_params: %{oauth_token_secret: binary()}}} | {:error, term()}
  def authorize_url(config) do
    case Config.fetch(config, :redirect_uri) do
      {:ok, redirect_uri} -> authorize_url(config, redirect_uri)
      {:error, error}     -> {:error, error}
    end
  end

  defp authorize_url(config, redirect_uri) do
    config
    |> get_request_token([{"oauth_callback", redirect_uri}])
    |> build_authorize_url(config)
    |> case do
      {:ok, url, oauth_token_secret} -> {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}}
      {:error, error}                -> {:error, error}
    end
  end

  defp get_request_token(config, params) do
    with {:ok, site} <- Config.fetch(config, :site),
         {:ok, consumer_key} <- Config.fetch(config, :consumer_key),
         {:ok, consumer_secret} <- Config.fetch(config, :consumer_secret) do
      request_token_url = Config.get(config, :request_token_url, "/oauth/request_token")
      url               = process_url(site, request_token_url)

      credentials =
        OAuther.credentials([
          consumer_key: consumer_key,
          consumer_secret: consumer_secret
        ])

      config
      |> do_request(:post, site, url, credentials, params)
      |> Helpers.decode_response(config)
      |> process_token_response()
    end
  end

  defp process_url(site, url) do
    case String.downcase(url) do
      <<"http://"::utf8, _::binary>>  -> url
      <<"https://"::utf8, _::binary>> -> url
      _                               -> site <> url
    end
  end

  defp do_request(config, method, site, url, credentials, params, headers \\ []) do
    params =
      params
      |> Enum.to_list()
      |> Enum.map(fn {key, value} -> {to_string(key), value} end)

    signed_params        = OAuther.sign(Atom.to_string(method), url, params, credentials)
    {header, req_params} = OAuther.header(signed_params)
    req_headers          = request_headers(method, [header] ++ headers)
    req_body             = request_body(method, req_params)
    params               = url_params(method, params)
    url                  = Helpers.to_url(site, url, params)

    Helpers.request(method, url, req_body, req_headers, config)
  end

  defp request_headers(:post, headers), do: [{"content-type", "application/x-www-form-urlencoded"}] ++ headers
  defp request_headers(_method, headers), do: headers

  defp request_body(:post, req_params), do: URI.encode_query(req_params)
  defp request_body(_method, _req_params), do: nil

  defp url_params(:post, _params), do: []
  defp url_params(_method, params), do: params

  defp process_token_response({:ok, %HTTPResponse{status: 200, body: body} = response}) when is_binary(body), do: process_token_response({:ok, %{response | body: URI.decode_query(body)}})
  defp process_token_response({:ok, %HTTPResponse{status: 200, body: %{"oauth_token" => _} = token}}), do: {:ok, token}
  defp process_token_response(any), do: process_response(any)

  defp process_response({:ok, %HTTPResponse{} = response}), do: {:error, RequestError.unexpected(response)}
  defp process_response({:error, %HTTPResponse{} = response}), do: {:error, RequestError.invalid(response)}
  defp process_response({:error, error}), do: {:error, error}

  defp build_authorize_url({:ok, token}, config) do
    with {:ok, site} <- Config.fetch(config, :site),
         {:ok, oauth_token} <- fetch_from_token(token, "oauth_token"),
         {:ok, oauth_token_secret} <- fetch_from_token(token, "oauth_token_secret") do
      authorization_url = Config.get(config, :authorize_url, "/oauth/authenticate")
      params            = authorization_params(config, oauth_token: oauth_token)
      url               = Helpers.to_url(site, authorization_url, params)

      {:ok, url, oauth_token_secret}
    end
  end
  defp build_authorize_url({:error, error}, _config), do: {:error, error}

  defp fetch_from_token(token, key) do
    case Map.fetch(token, key) do
      {:ok, value} -> {:ok, value}
      :error       -> {:error, "No `#{key}` in token map"}
    end
  end

  defp authorization_params(config, params) do
    config
    |> Config.get(:authorization_params, [])
    |> Config.merge(params)
    |> List.keysort(0)
  end

  @doc """
  Callback phase for generating access token and fetch user data.

  ## Configuration

    - `:access_token_url` - The path or URL to fetch the access token from,
      optional, defaults to `/oauth/access_token`
    - `:user_url` - The path or URL to fetch user data, required
    - `:session_params` - The session parameters that was returned from
      `authorize_url/1`, optional
  """
  @impl true
  @spec callback(Config.t(), map(), atom()) :: {:ok, %{user: map(), token: map()}} | {:error, term()}
  def callback(config, %{"oauth_token" => oauth_token, "oauth_verifier" => oauth_verifier}, strategy \\ __MODULE__) do
    with {:ok, token} <- get_access_token(config, oauth_token, oauth_verifier),
         {:ok, user}  <- strategy.fetch_user(config, token) do
      {:ok, %{user: user, token: token}}
    end
  end

  defp get_access_token(config, oauth_token, oauth_verifier) do
    with {:ok, site} <- Config.fetch(config, :site),
         {:ok, consumer_key} <- Config.fetch(config, :consumer_key),
         {:ok, consumer_secret} <- Config.fetch(config, :consumer_secret) do

      access_token_url   = Config.get(config, :access_token_url, "/oauth/access_token")
      url                = process_url(site, access_token_url)
      params             = [{"oauth_verifier", oauth_verifier}]
      oauth_token_secret = Kernel.get_in(config, [:session_params, :oauth_token_secret])

      credentials =
        OAuther.credentials([
          consumer_key: consumer_key,
          consumer_secret: consumer_secret,
          token: oauth_token,
          token_secret: oauth_token_secret
        ])

      config
      |> do_request(:post, site, url, credentials, params)
      |> Helpers.decode_response(config)
      |> process_token_response()
    end
  end

  @doc """
  Performs a signed HTTP request to the API using the oauth token.
  """
  @spec request(Config.t(), map(), atom(), binary(), map() | Keyword.t(), [{binary(), binary()}]) :: {:ok, map()} | {:error, term()}
  def request(config, token, method, url, params \\ [], headers \\ []) do
    with {:ok, site} <- Config.fetch(config, :site),
         {:ok, consumer_key} <- Config.fetch(config, :consumer_key),
         {:ok, consumer_secret} <- Config.fetch(config, :consumer_secret),
         {:ok, oauth_token} <- fetch_from_token(token, "oauth_token"),
         {:ok, oauth_token_secret} <- fetch_from_token(token, "oauth_token_secret") do
      url = process_url(site, url)

      credentials =
        OAuther.credentials([
          consumer_key: consumer_key,
          consumer_secret: consumer_secret,
          token: oauth_token,
          token_secret: oauth_token_secret
        ])

      config
      |> do_request(method, site, url, credentials, params, headers)
      |> Helpers.decode_response(config)
    end
  end

  @doc false
  @spec fetch_user(Config.t(), map()) :: {:ok, map()} | {:error, term()}
  def fetch_user(config, token) do
    with {:ok, url} <- Config.fetch(config, :user_url) do
      config
      |> request(token, :get, url)
      |> process_user_response()
    end
  end

  defp process_user_response({:ok, %HTTPResponse{status: 200, body: user}}), do: {:ok, user}
  defp process_user_response({:error, %HTTPResponse{status: 401}}), do: {:error, %RequestError{message: "Unauthorized token"}}
  defp process_user_response(any), do: process_response(any)
end
