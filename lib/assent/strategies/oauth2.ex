defmodule Assent.Strategy.OAuth2 do
  @moduledoc """
  OAuth 2.0 strategy.

  This strategy only supports the Authorization Code flow per
  [RFC 6749](https://tools.ietf.org/html/rfc6749#section-1.3.1).

  `authorize_url/1` returns a map with a `:url` and `:session_params` key. The
  `:session_params` should be stored and passed back into `callback/3` as part
  of config when the user returns. The `:session_params` carries a `:state`
  value for the request [to prevent
  CSRF](https://tools.ietf.org/html/rfc6749#section-4.1.1).

  This library also supports JWT tokens for client authentication as per
  [RFC 7523](https://tools.ietf.org/html/rfc7523).

  ## Configuration

    - `:client_id` - The OAuth2 client id, required
    - `:site` - The domain of the OAuth2 server, required
    - `:auth_method` - The authentication strategy used, optional. If not set,
      no authentication will be used during the access token request. The value
      may be one of the following:

      - `:client_secret_basic` - Authenticate with basic authorization header
      - `:client_secret_post` - Authenticate with post params
      - `:client_secret_jwt` - Authenticate with JWT using `:client_secret` as
        secret
      - `:private_key_jwt` - Authenticate with JWT using `:private_key_path` or
        `:private_key` as secret
    - `:client_secret` - The OAuth2 client secret, required if `:auth_method`
      is `:client_secret_basic`, `:client_secret_post`, or `:client_secret_jwt`
    - `:private_key_id` - The private key ID, required if `:auth_method` is
      `:private_key_jwt`
    - `:private_key_path` - The path for the private key, required if
      `:auth_method` is `:private_key_jwt` and `:private_key` hasn't been set
    - `:private_key` - The private key content that can be defined instead of
      `:private_key_path`, required if `:auth_method` is `:private_key_jwt` and
      `:private_key_path` hasn't been set
    - `:jwt_algorithm` - The algorithm to use for JWT signing, optional,
      defaults to `HS256` for `:client_secret_jwt` and `RS256` for
      `:private_key_jwt`

  ## Usage

      config =  [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        auth_method: :client_secret_post,
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
  alias Assent.{CallbackCSRFError, CallbackError, Config, HTTPAdapter.HTTPResponse, JWTAdapter, MissingParamError, RequestError}

  @doc """
  Generate authorization URL for request phase.

  ## Configuration

    - `:redirect_uri` - The URI that the server redirects the user to after
      authentication, required
    - `:authorize_url` - The path or URL for the OAuth2 server to redirect
      users to, defaults to `/oauth/authorize`
    - `:authorization_params` - The authorization parameters, defaults to `[]`
  """
  @impl true
  @spec authorize_url(Config.t()) :: {:ok, %{session_params: %{state: binary()}, url: binary()}} | {:error, term()}
  def authorize_url(config) do
    with {:ok, redirect_uri} <- Config.fetch(config, :redirect_uri),
         {:ok, site}         <- Config.fetch(config, :site),
         {:ok, client_id}    <- Config.fetch(config, :client_id) do
      state         = gen_state()
      params        = authorization_params(config, client_id, state, redirect_uri)
      authorize_url = Config.get(config, :authorize_url, "/oauth/authorize")
      url           = Helpers.to_url(site, authorize_url, params)

      {:ok, %{url: url, session_params: %{state: state}}}
    end
  end

  defp authorization_params(config, client_id, state, redirect_uri) do
    params = Config.get(config, :authorization_params, [])

    [
      response_type: "code",
      client_id: client_id,
      state: state,
      redirect_uri: redirect_uri]
    |> Keyword.merge(params)
    |> List.keysort(0)
  end

  @doc """
  Callback phase for generating access token and fetch user data.

  ## Configuration

    - `:token_url` - The path or URL to fetch the token from, optional,
      defaults to `/oauth/token`
    - `:user_url` - The path or URL to fetch user data, required
    - `:session_params` - The session parameters that was returned from
      `authorize_url/1`, optional
  """
  @impl true
  @spec callback(Config.t(), map(), atom()) :: {:ok, %{user: map(), token: map()}} | {:error, term()}
  def callback(config, params, strategy \\ __MODULE__) do
    with {:ok, session_params} <- Config.fetch(config, :session_params),
         :ok                   <- check_error_params(params),
         {:ok, code}           <- fetch_code_param(params),
         :ok                   <- maybe_check_state(session_params, params),
         {:ok, token}          <- get_access_token(config, code) do

      fetch_user(config, token, strategy)
    end
  end

  defp check_error_params(%{"error" => _} = params) do
    message   = params["error_description"] || params["error_reason"] || params["error"]
    error     = params["error"]
    error_uri = params["error_uri"]

    {:error, %CallbackError{message: message, error: error, error_uri: error_uri}}
  end
  defp check_error_params(_params), do: :ok

  defp fetch_code_param(%{"code" => code}), do: {:ok, code}
  defp fetch_code_param(params), do: {:error, MissingParamError.new("code", params)}

  defp maybe_check_state(%{state: stored_state}, %{"state" => provided_state}) do
    case Assent.constant_time_compare(stored_state, provided_state) do
      true -> :ok
      false -> {:error, CallbackCSRFError.new("state")}
    end
  end
  defp maybe_check_state(%{state: _state}, params) do
    {:error, MissingParamError.new("state", params)}
  end
  defp maybe_check_state(_session_params, _params), do: :ok

  defp authentication_params(nil, config) do
    with {:ok, client_id}     <- Config.fetch(config, :client_id) do

      headers = []
      body    = [client_id: client_id]

      {:ok, headers, body}
    end
  end
  defp authentication_params(:client_secret_basic, config) do
    with {:ok, client_id}     <- Config.fetch(config, :client_id),
         {:ok, client_secret} <- Config.fetch(config, :client_secret) do

      auth    = Base.url_encode64("#{client_id}:#{client_secret}", padding: false)
      headers = [{"authorization", "Basic #{auth}"}]
      body    = []

      {:ok, headers, body}
    end
  end
  defp authentication_params(:client_secret_post, config) do
    with {:ok, client_id}     <- Config.fetch(config, :client_id),
         {:ok, client_secret} <- Config.fetch(config, :client_secret) do

      headers = []
      body    = [client_id: client_id, client_secret: client_secret]

      {:ok, headers, body}
    end
  end
  defp authentication_params(:client_secret_jwt, config) do
    alg = Config.get(config, :jwt_algorithm, "HS256")

    with {:ok, client_secret} <- Config.fetch(config, :client_secret) do
      jwt_authentication_params(alg, client_secret, config)
    end
  end
  defp authentication_params(:private_key_jwt, config) do
    alg = Config.get(config, :jwt_algorithm, "RS256")

    with {:ok, pem}             <- JWTAdapter.load_private_key(config),
         {:ok, _private_key_id} <- Config.fetch(config, :private_key_id) do
      jwt_authentication_params(alg, pem, config)
    end
  end
  defp authentication_params(method, _config) do
    {:error, "Invalid `:auth_method` #{method}"}
  end

  defp jwt_authentication_params(alg, secret, config) do
    with {:ok, claims}    <- jwt_claims(config),
         {:ok, token}     <- Helpers.sign_jwt(claims, alg, secret, config) do

      headers = []
      body    = [client_assertion: token, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]

      {:ok, headers, body}
    end
  end

  defp jwt_claims(config) do
    timestamp = :os.system_time(:second)

    with {:ok, site}      <- Config.fetch(config, :site),
         {:ok, client_id} <- Config.fetch(config, :client_id) do

      {:ok, %{
        "iss" => client_id,
        "sub" => client_id,
        "aud" => site,
        "iat" => timestamp,
        "exp" => timestamp + 60
      }}
    end
  end

  defp get_access_token(config, code) do
    auth_method  = Config.get(config, :auth_method, nil)
    token_url    = Config.get(config, :token_url, "/oauth/token")

    with {:ok, site}                    <- Config.fetch(config, :site),
         {:ok, auth_headers, auth_body} <- authentication_params(auth_method, config),
         {:ok, redirect_uri}            <- Config.fetch(config, :redirect_uri) do
      headers = [{"content-type", "application/x-www-form-urlencoded"}] ++ auth_headers
      params  = Keyword.merge(auth_body, code: code, redirect_uri: redirect_uri, grant_type: "authorization_code")
      url     = Helpers.to_url(site, token_url)
      body    = URI.encode_query(params)

      :post
      |> Helpers.request(url, body, headers, config)
      |> Helpers.decode_response(config)
      |> process_access_token_response()
    end
  end

  defp process_access_token_response({:ok, %HTTPResponse{status: 200, body: %{"access_token" => _} = token}}), do: {:ok, token}
  defp process_access_token_response(any), do: process_response(any)

  defp process_response({:ok, %HTTPResponse{} = response}), do: {:error, RequestError.unexpected(response)}
  defp process_response({:error, %HTTPResponse{} = response}), do: {:error, RequestError.invalid(response)}
  defp process_response({:error, error}), do: {:error, error}

  defp fetch_user(config, token, strategy) do
    config
    |> strategy.get_user(token)
    |> case do
      {:ok, user}     -> {:ok, %{token: token, user: user}}
      {:error, error} -> {:error, error}
    end
  end

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
    access_token_type = Map.get(token, "token_type", "Bearer") |> String.capitalize()
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
