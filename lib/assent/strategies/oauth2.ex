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
    - `:base_url` - The base URL of the OAuth2 server, required
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
        base_url: "https://auth.example.com",
        authorization_params: [scope: "user:read user:write"],
        user_url: "https://example.com/api/user"
      ]

      {:ok, %{url: url, session_params: session_params}} =
        config
        |> Assent.Config.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> Assent.Strategy.OAuth2.authorize_url()

      {:ok, %{user: user, token: token}} =
        config
        |> Assent.Config.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> Assent.Config.put(:session_params, session_params)
        |> Assent.Strategy.OAuth2.callback(params)
  """
  @behaviour Assent.Strategy

  alias Assent.Strategy, as: Helpers

  alias Assent.{
    CallbackCSRFError,
    CallbackError,
    Config,
    HTTPAdapter.HTTPResponse,
    InvalidResponseError,
    JWTAdapter,
    MissingParamError,
    RequestError,
    UnexpectedResponseError
  }

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
  @spec authorize_url(Config.t()) ::
          {:ok, %{session_params: %{state: binary()}, url: binary()}} | {:error, term()}
  def authorize_url(config) do
    with {:ok, redirect_uri} <- Config.fetch(config, :redirect_uri),
         {:ok, base_url} <- Config.__base_url__(config),
         {:ok, client_id} <- Config.fetch(config, :client_id) do
      params = authorization_params(config, client_id, redirect_uri)
      authorize_url = Config.get(config, :authorize_url, "/oauth/authorize")
      url = Helpers.to_url(base_url, authorize_url, params)

      {:ok, %{url: url, session_params: %{state: params[:state]}}}
    end
  end

  defp authorization_params(config, client_id, redirect_uri) do
    params = Config.get(config, :authorization_params, [])

    [
      response_type: "code",
      client_id: client_id,
      state: gen_state(),
      redirect_uri: redirect_uri
    ]
    |> Keyword.merge(params)
    |> List.keysort(0)
  end

  defp gen_state do
    24
    |> :crypto.strong_rand_bytes()
    |> :erlang.bitstring_to_list()
    |> Enum.map_join(fn x -> :erlang.integer_to_binary(x, 16) end)
    |> String.downcase()
  end

  @doc """
  Callback phase for generating access token with authorization code and fetch
  user data. Returns a map with access token in `:token` and user data in
  `:user`.

  ## Configuration

    - `:token_url` - The path or URL to fetch the token from, optional,
      defaults to `/oauth/token`
    - `:user_url` - The path or URL to fetch user data, required
    - `:session_params` - The session parameters that was returned from
      `authorize_url/1`, optional
  """
  @impl true
  @spec callback(Config.t(), map(), atom()) ::
          {:ok, %{user: map(), token: map()}} | {:error, term()}
  def callback(config, params, strategy \\ __MODULE__) do
    with {:ok, session_params} <- Config.fetch(config, :session_params),
         :ok <- check_error_params(params),
         {:ok, code} <- fetch_code_param(params),
         {:ok, redirect_uri} <- Config.fetch(config, :redirect_uri),
         :ok <- maybe_check_state(session_params, params),
         {:ok, token} <-
           grant_access_token(
             config,
             "authorization_code",
             code: code,
             redirect_uri: redirect_uri
           ) do
      fetch_user_with_strategy(config, token, strategy)
    end
  end

  defp check_error_params(%{"error" => _} = params) do
    message = params["error_description"] || params["error_reason"] || params["error"]
    error = params["error"]
    error_uri = params["error_uri"]

    {:error, CallbackError.exception(message: message, error: error, error_uri: error_uri)}
  end

  defp check_error_params(_params), do: :ok

  defp fetch_code_param(%{"code" => code}), do: {:ok, code}

  defp fetch_code_param(params),
    do: {:error, MissingParamError.exception(expected_key: "code", params: params)}

  defp maybe_check_state(%{state: stored_state}, %{"state" => provided_state}) do
    case Assent.constant_time_compare(stored_state, provided_state) do
      true -> :ok
      false -> {:error, CallbackCSRFError.exception(key: "state")}
    end
  end

  defp maybe_check_state(%{state: _state}, params) do
    {:error, MissingParamError.exception(expected_key: "state", params: params)}
  end

  defp maybe_check_state(_session_params, _params), do: :ok

  defp authentication_params(nil, config) do
    with {:ok, client_id} <- Config.fetch(config, :client_id) do
      headers = []
      body = [client_id: client_id]

      {:ok, headers, body}
    end
  end

  defp authentication_params(:client_secret_basic, config) do
    with {:ok, client_id} <- Config.fetch(config, :client_id),
         {:ok, client_secret} <- Config.fetch(config, :client_secret) do
      auth = Base.encode64("#{client_id}:#{client_secret}")
      headers = [{"authorization", "Basic #{auth}"}]
      body = []

      {:ok, headers, body}
    end
  end

  defp authentication_params(:client_secret_post, config) do
    with {:ok, client_id} <- Config.fetch(config, :client_id),
         {:ok, client_secret} <- Config.fetch(config, :client_secret) do
      headers = []
      body = [client_id: client_id, client_secret: client_secret]

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

    with {:ok, pem} <- JWTAdapter.load_private_key(config),
         {:ok, _private_key_id} <- Config.fetch(config, :private_key_id) do
      jwt_authentication_params(alg, pem, config)
    end
  end

  defp authentication_params(method, _config) do
    {:error, "Invalid `:auth_method` #{method}"}
  end

  defp jwt_authentication_params(alg, secret, config) do
    with {:ok, claims} <- jwt_claims(config),
         {:ok, token} <- Helpers.sign_jwt(claims, alg, secret, config) do
      headers = []

      body = [
        client_assertion: token,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      ]

      {:ok, headers, body}
    end
  end

  defp jwt_claims(config) do
    timestamp = :os.system_time(:second)

    with {:ok, base_url} <- Config.__base_url__(config),
         {:ok, client_id} <- Config.fetch(config, :client_id) do
      {:ok,
       %{
         "iss" => client_id,
         "sub" => client_id,
         "aud" => base_url,
         "iat" => timestamp,
         "exp" => timestamp + 60
       }}
    end
  end

  @doc """
  Grants an access token.
  """
  @spec grant_access_token(Config.t(), binary(), Keyword.t()) :: {:ok, map()} | {:error, term()}
  def grant_access_token(config, grant_type, params) do
    auth_method = Config.get(config, :auth_method, nil)
    token_url = Config.get(config, :token_url, "/oauth/token")

    with {:ok, base_url} <- Config.__base_url__(config),
         {:ok, auth_headers, auth_body} <- authentication_params(auth_method, config) do
      headers = [{"content-type", "application/x-www-form-urlencoded"}] ++ auth_headers
      params = Keyword.merge(params, Keyword.put(auth_body, :grant_type, grant_type))
      url = Helpers.to_url(base_url, token_url)
      body = URI.encode_query(params)

      :post
      |> Helpers.request(url, body, headers, config)
      |> process_access_token_response()
    end
  end

  defp process_access_token_response(
         {:ok, %HTTPResponse{status: status, body: %{"access_token" => _} = token}}
       )
       when status in [200, 201] do
    {:ok, token}
  end

  defp process_access_token_response(any), do: process_response(any)

  defp process_response({:ok, %HTTPResponse{} = response}),
    do: {:error, UnexpectedResponseError.exception(response: response)}

  defp process_response({:error, %HTTPResponse{} = response}),
    do: {:error, InvalidResponseError.exception(response: response)}

  defp process_response({:error, error}), do: {:error, error}

  defp fetch_user_with_strategy(config, token, strategy) do
    config
    |> strategy.fetch_user(token)
    |> case do
      {:ok, user} -> {:ok, %{token: token, user: user}}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Refreshes the access token.
  """
  @spec refresh_access_token(Config.t(), map(), Keyword.t()) :: {:ok, map()} | {:error, term()}
  def refresh_access_token(config, token, params \\ []) do
    with {:ok, refresh_token} <- fetch_from_token(token, "refresh_token") do
      grant_access_token(
        config,
        "refresh_token",
        Keyword.put(params, :refresh_token, refresh_token)
      )
    end
  end

  @doc """
  Performs a HTTP request to the API using the access token.
  """
  @spec request(Config.t(), map(), atom(), binary(), map() | Keyword.t(), [{binary(), binary()}]) ::
          {:ok, map()} | {:error, term()}
  def request(config, token, method, url, params \\ [], headers \\ []) do
    with {:ok, base_url} <- Config.__base_url__(config),
         {:ok, auth_headers} <- authorization_headers(config, token) do
      req_headers = request_headers(method, auth_headers ++ headers)
      req_body = request_body(method, params)
      params = url_params(method, params)
      url = Helpers.to_url(base_url, url, params)

      Helpers.request(method, url, req_body, req_headers, config)
    end
  end

  defp request_headers(:post, headers),
    do: [{"content-type", "application/x-www-form-urlencoded"}] ++ headers

  defp request_headers(_method, headers), do: headers

  defp request_body(:post, params), do: URI.encode_query(params)
  defp request_body(_method, _params), do: nil

  defp url_params(:post, _params), do: []
  defp url_params(_method, params), do: params

  @doc """
  Fetch user data with the access token.

  Uses `request/6` to fetch the user data.
  """
  @spec fetch_user(Config.t(), map(), map() | Keyword.t(), [{binary(), binary()}]) ::
          {:ok, map()} | {:error, term()}
  def fetch_user(config, token, params \\ [], headers \\ []) do
    with {:ok, user_url} <- Config.fetch(config, :user_url) do
      config
      |> request(token, :get, user_url, params, headers)
      |> process_user_response()
    end
  end

  defp authorization_headers(config, token) do
    type =
      token
      |> Map.get("token_type", "Bearer")
      |> String.downcase()

    authorization_headers(config, token, type)
  end

  defp authorization_headers(_config, token, "bearer") do
    with {:ok, access_token} <- fetch_from_token(token, "access_token") do
      {:ok, [{"authorization", "Bearer #{access_token}"}]}
    end
  end

  defp authorization_headers(_config, _token, type) do
    {:error, "Authorization with token type `#{type}` not supported"}
  end

  defp fetch_from_token(token, key) do
    case Map.fetch(token, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, "No `#{key}` in token map"}
    end
  end

  defp process_user_response({:ok, %HTTPResponse{status: 200, body: user}}), do: {:ok, user}

  defp process_user_response({:error, %HTTPResponse{status: 401} = response}),
    do: {:error, RequestError.exception(message: "Unauthorized token", response: response)}

  defp process_user_response(any), do: process_response(any)
end
