defmodule Assent.Strategy.OAuth2 do
  @moduledoc """
  OAuth 2.0 strategy.

  `authorize_url/1` returns a map with a `:session_params` and `:url` key. The
  `:session_params` key carries a `:state` value for the request.

  ## Configuration

    - `:client_id` - The OAuth2 client id, required
    - `:client_secret` - The OAuth2 client secret, required
    - `:site` - The domain of the OAuth2 server, required

  ## Usage

      config =  [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        site: "https://auth.example.com",
        authorization_params: [scope: "user:read user:write"],
        user_url: "https://example.com/api/user"
      ]

      {:ok, {url: url, session_params: session_params}} =
        config
        |> Assent.Config.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> Assent.Strategy.OAuth2.authorize_url()

      {:ok, %{user: user, token: token}} =
        config
        |> Assent.Config.put(:session_params, session_params)
        |> Assent.Strategy.OAuth2.callback(params)
  """
  @behaviour Assent.Strategy

  alias Assent.Strategy, as: Helpers
  alias Assent.{CallbackCSRFError, CallbackError, Config, HTTPAdapter.HTTPResponse, RequestError}

  @doc """
  Generate authorization URL for request phase.

  ## Configuration

    - `:redirect_uri` - The URI that the server redirects the user to after authentication, required
    - `:authorize_url` - The path or URL for the OAuth2 server to redirect users to, defaults to "/oauth/authorize"
    - `:authorization_params` - The authorization parameters, defaults to `[]`
  """
  @spec authorize_url(Config.t()) :: {:ok, %{session_params: %{state: binary()}, url: binary()}} | {:error, term()}
  def authorize_url(config) do
    with {:ok, redirect_uri} <- Config.fetch(config, :redirect_uri),
         {:ok, site} <- Config.fetch(config, :site),
         state <- gen_state(),
         {:ok, params} <- authorization_params(config, state: state, redirect_uri: redirect_uri) do

      authorize_url = Config.get(config, :authorize_url, "/oauth/authorize")
      url           = Helpers.to_url(site, authorize_url, params)

      {:ok, %{url: url, session_params: %{state: state}}}
    end
  end

  defp authorization_params(config, params) do
    with {:ok, client_id} <- Config.fetch(config, :client_id) do
      default   = [response_type: "code", client_id: client_id]
      custom    = Config.get(config, :authorization_params, [])

      params =
        default
        |> Keyword.merge(custom)
        |> Keyword.merge(params)
        |> List.keysort(0)

      {:ok, params}
    end
  end

  @doc """
  Callback phase for generating access token and fetch user data.

  ## Configuration

    - `:token_url` - The path or URL to fetch the token from, optional, defaults to "/oauth/token"
    - `:user_url` - The path or URL to fetch user data, required
    - `:session_params` - The session parameters that was returned from `authorize_url/1`, optional
  """
  @spec callback(Config.t(), map(), atom()) :: {:ok, %{user: map(), token: map()}} | {:error, term()}
  def callback(config, params, strategy \\ __MODULE__) do
    config
    |> Config.get(:session_params, nil)
    |> check_state(params)
    |> get_access_token(params, config)
    |> fetch_user(config, strategy)
  end

  defp check_state(_params, %{"error" => _} = params) do
    message   = params["error_description"] || params["error_reason"] || params["error"]
    error     = params["error"]
    error_uri = params["error_uri"]

    {:error, %CallbackError{message: message, error: error, error_uri: error_uri}}
  end
  defp check_state(%{state: stored_state}, %{"state" => param_state}) when stored_state != param_state,
    do: {:error, %CallbackCSRFError{}}
  defp check_state(_state, _params), do: :ok

  defp get_access_token(:ok, %{"code" => code, "redirect_uri" => redirect_uri}, config) do
    with {:ok, client_secret} <- Config.fetch(config, :client_secret),
         {:ok, params} <- authorization_params(config, code: code, client_secret: client_secret, redirect_uri: redirect_uri, grant_type: "authorization_code"),
         {:ok, site} <- Config.fetch(config, :site) do

      token_url     = Config.get(config, :token_url, "/oauth/token")
      url           = Helpers.to_url(site, token_url)
      headers       = [{"content-type", "application/x-www-form-urlencoded"}]
      body          = URI.encode_query(params)

      :post
      |> Helpers.request(url, body, headers, config)
      |> Helpers.decode_response(config)
      |> process_access_token_response()
    end
  end
  defp get_access_token({:error, error}, _params, _config), do: {:error, error}

  defp process_access_token_response({:ok, %HTTPResponse{status: 200, body: %{"access_token" => _} = token}}), do: {:ok, token}
  defp process_access_token_response(any), do: process_response(any)

  defp process_response({:ok, %HTTPResponse{} = response}), do: {:error, RequestError.unexpected(response)}
  defp process_response({:error, %HTTPResponse{} = response}), do: {:error, RequestError.invalid(response)}
  defp process_response({:error, error}), do: {:error, error}

  defp fetch_user({:ok, token}, config, strategy) do
    config
    |> strategy.get_user(token)
    |> case do
      {:ok, user} -> {:ok, %{token: token, user: user}}
      {:error, error} -> {:error, error}
    end
  end
  defp fetch_user({:error, error}, _config, _strategy),
    do: {:error, error}

  @doc """
  Makes a HTTP get request to the API.

  JSON responses will be decoded to maps.
  """
  @spec get(Config.t(), map(), binary(), map() | Keyword.t()) :: {:ok, map()} | {:error, term()}
  def get(config, token, url, params \\ []) do
    with {:ok, site} <- Config.fetch(config, :site) do
      url     = Helpers.to_url(site, url, params)
      headers = authorization_headers(config, token)

      :get
      |> Helpers.request(url, nil, headers, config)
      |> Helpers.decode_response(config)
    end
  end

  @spec get_user(Config.t(), map(), map() | Keyword.t()) :: {:ok, map()} | {:error, term()}
  def get_user(config, token, params \\ []) do
    case Config.fetch(config, :user_url) do
      {:ok, user_url} ->
        config
        |> get(token, user_url, params)
        |> process_user_response()

      {:error, error} ->
        {:error, error}
    end
  end

  @spec authorization_headers(Config.t(), map()) :: [{binary(), binary()}]
  def authorization_headers(_config, token) do
    access_token_type = Map.get(token, "token_type", "Bearer")
    access_token = token["access_token"]

    [{"authorization", "#{access_token_type} #{access_token}"}]
  end

  defp process_user_response({:ok, %HTTPResponse{status: 200, body: user}}), do: {:ok, user}
  defp process_user_response({:error, %HTTPResponse{status: 401}}), do: {:error, %RequestError{message: "Unauthorized token"}}
  defp process_user_response(any), do: process_response(any)

  defp gen_state do
    24
    |> :crypto.strong_rand_bytes()
    |> :erlang.bitstring_to_list()
    |> Enum.map(fn x -> :erlang.integer_to_binary(x, 16) end)
    |> Enum.join()
    |> String.downcase()
  end
end
