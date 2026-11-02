defmodule Assent.Strategy.OIDC do
  @moduledoc """
  OpenID Connect strategy.

  This is built upon the `Assent.Strategy.OAuth2` strategy with added OpenID
  Connect capabilities.

  ## Configuration

    * `:client_id` - the client ID, required

    * `:base_url` - the OIDC issuer, required, must exactly match the
      discovered `issuer`

    * `:openid_configuration_uri` - the URI for OpenID Provider, optional,
      defaults to `/.well-known/openid-configuration`

    * `:client_authentication_method` - the Client Authentication method to
      use, optional, defaults to `client_secret_basic`. The value may be one
      of the following:

      * `none` - no client authentication, used with public clients

      * `client_secret_basic` - authenticate with basic authorization header

      * `client_secret_post` - authenticate with post params

      * `client_secret_jwt` - authenticate with JWT using `:client_secret` as
        secret

      * `private_key_jwt` - authenticate with JWT using `:private_key_path` or
        `:private_key` as secret

    * `:client_secret` - the client secret, required if
      `:client_authentication_method` is `client_secret_basic`,
      `:client_secret_post`, or `:client_secret_jwt`

    * `:openid_configuration` - the OpenID configuration, optional, the
      configuration will be fetched from `:openid_configuration_uri` if this is
      not defined

    * `:id_token_signed_response_alg` - the `id_token_signed_response_alg`
      parameter sent by the Client during Registration, defaults to `RS256`

    * `:userinfo_signed_response_alg` - the `userinfo_signed_response_alg`
      parameter sent by the Client during Registration, required for signed
      UserInfo responses

    * `:id_token_ttl_seconds` - the number of seconds from `iat` that an ID
      Token will be considered valid, optional, defaults to nil

    * `:nonce` - the nonce to use for authorization request, optional, MUST be
      session based and unguessable

    * `:trusted_audiences` - a list of audiences to trust in addition to the
      client_id, optional

    * `:trusted_issuers` - a list of issuers to trust in addition to the
      provider's issuer, optional. The OIDC spec requires `iss` to match
      exactly, so only set this for providers that issue under more than one
      issuer.

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      defmodule OIDCAuth do
        import Plug.Conn

        alias Assent.Strategy.OIDC

        defp config do
          [
            client_id: Application.fetch_env!(:my_app, :oidc, :client_id),
            client_secret: Application.fetch_env!(:my_app, :oidc, :client_secret),
            base_url: "https://server.example.com",
            authorization_params: [scope: "user:read user:write"],
            redirect_uri: "http://localhost:4000/auth/callback"
          ]
        end

        def request(conn) do
          config()
          |> OIDC.authorize_url()
          |> case do
            {:ok, %{url: url, session_params: session_params}} ->
              conn
              |> put_session(:session_params, session_params)
              |> put_resp_header("location", url)
              |> send_resp(302, "")

            {:error, _error} ->
              send_resp(conn, 500, "Failed authorization")
          end
        end

        def callback(conn) do
          %{params: params} = fetch_query_params(conn)
          session_params = get_session(conn, :session_params)
          conn = delete_session(conn, :session_params)

          config()
          |> Keyword.put(:session_params, session_params)
          |> OIDC.callback(params)
          |> case do
            {:ok, %{user: user, token: token}} ->
              conn
              |> put_session(:user, user)
              |> put_session(:token, token)
              |> put_resp_header("location", "/")
              |> send_resp(302, "")

            {:error, _error} ->
              send_resp(conn, 500, "Failed authorization")
          end
        end
      end

  ## Nonce

  `:nonce` can be set in the provider config. The `:nonce` will be returned in
  the `:session_params` along with `:state`. You can use this to store the value
  in the current session e.g. an `HttpOnly` session cookie.

  A random value generator can look like this:

      16
      |> :crypto.strong_rand_bytes()
      |> Base.encode64(padding: false)

  Assent will dynamically generate one for the session if `:nonce` is set to
  `true`.

  See `Assent.Strategy.OIDC.authorize_url/1` for more.
  """

  defmodule InvalidOpenIDConfigurationError do
    @moduledoc """
    An exception for when an OpenID Connect Provider configuration is invalid.

    ## Fields

      * `:message` - a description of the error

    ## Examples

        iex> error = Assent.Strategy.OIDC.InvalidOpenIDConfigurationError.exception(message: "invalid OpenID Provider configuration")
        iex> Exception.message(error)
        "invalid OpenID Provider configuration"
    """

    defexception [:message]

    @type t :: %__MODULE__{message: binary()}
  end

  defmodule InvalidIDTokenError do
    @moduledoc """
    An exception for when an OpenID Connect ID Token is invalid.

    The `:reason` field is omitted from `Inspect` output as it may contain
    sensitive data.

    ## Fields

      * `:message` - a description of the error
      * `:reason` - the underlying failure reason, if any

    ## Examples

        iex> error = %Assent.Strategy.OIDC.InvalidIDTokenError{
        ...>   message: "invalid ID Token",
        ...>   reason: :invalid_signature
        ...> }
        iex> Exception.message(error)
        "invalid ID Token"
        iex> inspect(error)
        "#Assent.Strategy.OIDC.InvalidIDTokenError<message: \\"invalid ID Token\\", ...>"
    """

    @derive {Inspect, only: [:message]}
    defexception [:message, :reason]

    @type t :: %__MODULE__{message: binary(), reason: term() | nil}
  end

  defmodule InvalidUserInfoError do
    @moduledoc """
    An exception for when an OpenID Connect UserInfo response is invalid.

    The `:reason` field is omitted from `Inspect` output as it may contain
    sensitive data.

    ## Fields

      * `:message` - a description of the error
      * `:reason` - the underlying failure reason, if any

    ## Examples

        iex> error = %Assent.Strategy.OIDC.InvalidUserInfoError{
        ...>   message: "invalid UserInfo response",
        ...>   reason: :invalid_signature
        ...> }
        iex> Exception.message(error)
        "invalid UserInfo response"
        iex> inspect(error)
        "#Assent.Strategy.OIDC.InvalidUserInfoError<message: \\"invalid UserInfo response\\", ...>"
    """

    @derive {Inspect, only: [:message]}
    defexception [:message, :reason]

    @type t :: %__MODULE__{message: binary(), reason: term() | nil}
  end

  @behaviour Assent.Strategy

  alias Assent.{HTTPAdapter.HTTPResponse, Strategy.OAuth2}
  alias Assent.HTTPAdapter.{InvalidResponseError, RequestError, UnexpectedResponseError}
  alias Assent.Strategy, as: Helpers

  alias Assent.Strategy.OIDC.{
    InvalidIDTokenError,
    InvalidOpenIDConfigurationError,
    InvalidUserInfoError
  }

  @typedoc """
  The session parameters returned from `authorize_url/1`, to be stored and
  passed back into `callback/3`.
  """
  @type session_params :: %{
          optional(:state) => binary(),
          optional(:code_verifier) => binary(),
          optional(:code_challenge) => binary(),
          optional(:code_challenge_method) => binary(),
          optional(:nonce) => binary()
        }

  @typedoc "Return value of `authorize_url/1`."
  @type on_authorize_url :: OAuth2.on_authorize_url()

  @typedoc "Return value of `callback/3`."
  @type on_callback :: OAuth2.on_callback()

  @doc """
  Generates an authorization URL for the request phase.

  The authorization URL will be fetched from the OpenID configuration URI.

  `openid` will automatically be added to the `:scope` in
  `:authorization_params`, unless `:openid_default_scope` has been set.

  Add `:nonce` to the config to pass it with the authorization request. The
  nonce will be returned in `:session_params`. The nonce MUST be session based
  and unguessable. A cryptographic hash of a cryptographically random value
  could be stored in an `HttpOnly` session cookie.

  See `Assent.Strategy.OAuth2.authorize_url/1` for more.
  """
  @impl true
  @spec authorize_url(Keyword.t()) :: on_authorize_url()
  def authorize_url(config) do
    with {:ok, openid_config} <- fetch_openid_configuration(config),
         {:ok, authorize_url} <- fetch_from_openid_config(openid_config, "authorization_endpoint"),
         {:ok, params} <- fetch_authorization_params(config) do
      config
      |> Keyword.put(:authorization_params, params)
      |> Keyword.put(:authorize_url, authorize_url)
      |> OAuth2.authorize_url()
      |> add_nonce_to_session_params(params)
    end
  end

  defp fetch_openid_configuration(config) do
    case Keyword.get(config, :openid_configuration, nil) do
      nil -> fetch_openid_configuration_from_uri(config)
      openid_config -> {:ok, openid_config}
    end
  end

  defp fetch_openid_configuration_from_uri(config) do
    with {:ok, base_url} <- Assent.fetch_config(config, :base_url) do
      configuration_url =
        Keyword.get(config, :openid_configuration_uri, "/.well-known/openid-configuration")

      url = Helpers.to_url(base_url, configuration_url)

      case Helpers.http_request(:get, url, nil, [], config) do
        {:ok, %HTTPResponse{status: 200, body: configuration}} ->
          validate_provider_configuration_issuer(configuration, base_url)

        {:ok, %HTTPResponse{} = response} ->
          {:error, UnexpectedResponseError.exception(response: response)}

        {:error, %HTTPResponse{} = response} ->
          {:error, InvalidResponseError.exception(response: response)}

        {:error, error} ->
          {:error, error}
      end
    end
  end

  defp validate_provider_configuration_issuer(configuration, base_url) do
    with {:ok, issuer} <- fetch_from_openid_config(configuration, "issuer"),
         :ok <- do_validate_provider_configuration_issuer(issuer, base_url) do
      {:ok, configuration}
    end
  end

  defp do_validate_provider_configuration_issuer(issuer, issuer), do: :ok

  defp do_validate_provider_configuration_issuer(issuer, base_url) do
    {:error,
     InvalidOpenIDConfigurationError.exception(
       message: "expected `issuer` to be #{inspect(base_url)}, got: #{inspect(issuer)}"
     )}
  end

  defp fetch_from_openid_config(config, key) do
    case Map.fetch(config, key) do
      {:ok, value} ->
        {:ok, value}

      :error ->
        {:error,
         InvalidOpenIDConfigurationError.exception(
           message: "expected `#{key}` in OpenID Provider configuration"
         )}
    end
  end

  defp fetch_authorization_params(config) do
    new_params =
      config
      |> Keyword.get(:authorization_params, [])
      |> add_default_scope_param(config)
      |> Keyword.merge(nonce_params(config))

    {:ok, new_params}
  end

  defp nonce_params(config) do
    case Keyword.get(config, :nonce, false) do
      nonce when is_binary(nonce) -> [nonce: nonce]
      true -> [nonce: gen_nonce()]
      false -> []
    end
  end

  defp gen_nonce do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.encode64(padding: false)
  end

  defp add_default_scope_param(params, config) do
    default = Keyword.get(config, :openid_default_scope, "openid")

    case Keyword.fetch(params, :scope) do
      :error -> Keyword.put(params, :scope, default)
      {:ok, scope} -> Keyword.put(params, :scope, String.trim("#{default} #{scope}"))
    end
  end

  defp add_nonce_to_session_params({:ok, resp}, params) do
    case Keyword.fetch(params, :nonce) do
      {:ok, nonce} ->
        session_params =
          resp
          |> Map.get(:session_params, %{})
          |> Map.put(:nonce, nonce)

        {:ok, Map.put(resp, :session_params, session_params)}

      :error ->
        {:ok, resp}
    end
  end

  defp add_nonce_to_session_params({:error, error}, _params),
    do: {:error, error}

  @doc """
  Callback phase for generating an access token and fetching user data.

  The token URL will be fetched from the OpenID configuration URI.

  If the returned ID Token is signed with a symmetric key, `:client_secret`
  will be required and used to verify the ID Token. If it was signed with a
  private key, the appropriate public key will be fetched from the `jwks_uri`
  setting in the OpenID configuration to verify the ID Token.

  The ID Token will be validated per
  [OpenID Connect Core 1.0 rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

  See `Assent.Strategy.OAuth2.callback/3` for more.
  """
  @impl true
  @spec callback(Keyword.t(), map(), atom()) :: on_callback()
  def callback(config, params, strategy \\ __MODULE__) do
    with {:ok, openid_config} <- fetch_openid_configuration(config),
         {:ok, method} <- fetch_client_authentication_method(config),
         {:ok, token_url} <- fetch_from_openid_config(openid_config, "token_endpoint") do
      config
      |> Keyword.put(:openid_configuration, openid_config)
      |> Keyword.put(:auth_method, method)
      |> Keyword.put(:token_url, token_url)
      |> OAuth2.callback(params, strategy)
    end
  end

  defp fetch_client_authentication_method(config) do
    config
    |> Keyword.get(:client_authentication_method, "client_secret_basic")
    |> parse_client_auth_method()
  end

  defp parse_client_auth_method("none"), do: {:ok, nil}
  defp parse_client_auth_method("client_secret_basic"), do: {:ok, :client_secret_basic}
  defp parse_client_auth_method("client_secret_post"), do: {:ok, :client_secret_post}
  defp parse_client_auth_method("client_secret_jwt"), do: {:ok, :client_secret_jwt}
  defp parse_client_auth_method("private_key_jwt"), do: {:ok, :private_key_jwt}

  defp parse_client_auth_method(method),
    do:
      {:error,
       ArgumentError.exception("invalid client authentication method, got: #{inspect(method)}")}

  # https://openid.net/specs/draft-jones-json-web-token-07.html#ReservedClaimName
  @reserved_jwt_names ~w(exp nbf iat iss aud prn jti typ)

  # https://openid.net/specs/openid-connect-core-1_0.html#IDToken
  @id_token_names ~w(iss sub aud exp iat auth_time nonce acr amr azp at_hash c_hash sub_jwk)

  # All ID Token claim names to be excluded from the user params
  @id_token_names_to_exclude Enum.uniq(@reserved_jwt_names ++ (@id_token_names -- ~w(sub)))

  @doc """
  Fetches user params from ID token.

  The ID Token is validated, and the claims are returned as the user params.
  Use `fetch_userinfo/2` to fetch the claims from the `userinfo` endpoint.
  """
  @spec fetch_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}
  def fetch_user(config, token) do
    with {:ok, id_token} <- fetch_id_token(token),
         {:ok, jwt} <- validate_id_token(config, id_token) do
      {:ok, Map.drop(jwt.claims, @id_token_names_to_exclude)}
    end
  end

  defp fetch_id_token(token), do: Assent.fetch_token_param(token, "id_token")

  @doc """
  Validates the ID token.

  The OpenID configuration will be dynamically fetched if not set in the
  config.

  The ID Token will be validated per
  [OpenID Connect Core 1.0 rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
  """
  @spec validate_id_token(Keyword.t(), binary()) :: {:ok, map()} | {:error, term()}
  def validate_id_token(config, id_token) do
    case fetch_openid_configuration(config) do
      {:ok, openid_config} -> validate_id_token(config, id_token, openid_config)
      {:error, error} -> {:error, error}
    end
  end

  defp validate_id_token(config, id_token, openid_config) do
    expected_alg = Keyword.get(config, :id_token_signed_response_alg, "RS256")

    with {:ok, client_id} <- Assent.fetch_config(config, :client_id),
         {:ok, issuer} <- fetch_from_openid_config(openid_config, "issuer"),
         {:ok, jwt} <- verify_jwt(id_token, expected_alg, openid_config, config),
         :ok <- validate_required_fields(jwt, ~w(iss sub aud exp iat)),
         :ok <- validate_issuer_identifier(jwt, issuer, config),
         :ok <- validate_audience(jwt, client_id, config),
         :ok <- validate_authorization_party(jwt, client_id, config),
         :ok <- validate_expiration(jwt),
         :ok <- validate_issued_at(jwt, config),
         :ok <- validate_nonce(jwt, config) do
      {:ok, jwt}
    else
      {:error, message} when is_binary(message) ->
        {:error, InvalidIDTokenError.exception(message: message)}

      {:error, message, reason} ->
        {:error, InvalidIDTokenError.exception(message: message, reason: reason)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp verify_jwt(token, expected_alg, openid_config, config) do
    # Trust claims only after verification: https://www.rfc-editor.org/rfc/rfc7519.html#section-11.1
    with {:ok, header} <- peek_header(token, config),
         :ok <- validate_alg(header, expected_alg),
         {:ok, secret_or_key} <- fetch_secret(header, openid_config, config) do
      case Helpers.verify_jwt(token, secret_or_key, config) do
        {:ok, %{verified?: true} = jwt} -> {:ok, jwt}
        {:ok, %{verified?: false}} -> {:error, "expected JWT signature to be valid"}
        {:error, reason} -> {:error, "could not verify JWT", reason}
      end
    end
  end

  defp peek_header(encoded, config) do
    with {:ok, header} <- split_header(encoded),
         {:ok, json} <- decode_base64_url_header(header) do
      case Assent.json_library(config).decode(json) do
        {:ok, %{} = header} -> {:ok, header}
        {:ok, _value} -> {:error, "expected JWT header to be a JSON object"}
        {:error, reason} -> {:error, "could not decode JWT header", reason}
      end
    end
  end

  defp split_header(encoded) do
    case String.split(encoded, ".") do
      [header, _, _] -> {:ok, header}
      parts -> {:error, "expected JWT to have three parts, got: #{length(parts)}"}
    end
  end

  defp decode_base64_url_header(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, "expected JWT header to be base64url-encoded"}
    end
  end

  defp validate_alg(%{"alg" => alg}, alg), do: :ok

  defp validate_alg(%{"alg" => alg}, expected_alg),
    do:
      {:error,
       "expected `alg` in JWT header to be #{inspect(expected_alg)}, got: #{inspect(alg)}"}

  defp validate_alg(header, _expected_alg) do
    header_keys = header |> Map.keys() |> Enum.sort() |> inspect()

    {:error, "expected `alg` in JWT header, got: #{header_keys}"}
  end

  defp fetch_secret(%{"alg" => "none"}, _openid_config, _config), do: {:ok, ""}

  defp fetch_secret(%{"alg" => "HS" <> _rest}, _openid_config, config) do
    Assent.fetch_config(config, :client_secret)
  end

  defp fetch_secret(header, openid_config, config) do
    with {:ok, jwks_uri} <- fetch_from_openid_config(openid_config, "jwks_uri"),
         {:ok, keys} <- fetch_public_keys(jwks_uri, config) do
      find_key(header, keys)
    end
  end

  defp fetch_public_keys(uri, config) do
    case Helpers.http_request(:get, uri, nil, [], config) do
      {:ok, %HTTPResponse{status: 200, body: %{"keys" => keys}}} ->
        {:ok, keys}

      {:ok, %HTTPResponse{status: 200}} ->
        {:ok, []}

      {:ok, %HTTPResponse{} = response} ->
        {:error, UnexpectedResponseError.exception(response: response)}

      {:error, %HTTPResponse{} = response} ->
        {:error, InvalidResponseError.exception(response: response)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp find_key(_header, []),
    do:
      {:error,
       InvalidOpenIDConfigurationError.exception(
         message: "expected `jwks_uri` in OpenID Provider configuration to contain keys"
       )}

  defp find_key(%{"kid" => kid}, keys) do
    case Enum.find(keys, fn
           %{"kid" => key_id} -> key_id == kid
           _key -> false
         end) do
      nil ->
        key_ids =
          keys
          |> Enum.flat_map(fn
            %{"kid" => key_id} -> [key_id]
            _key -> []
          end)
          |> Enum.sort()
          |> inspect()

        {:error, "expected provider key IDs to include #{inspect(kid)}, got: #{key_ids}"}

      key ->
        {:ok, key}
    end
  end

  defp find_key(_header, [key]), do: {:ok, key}

  defp find_key(_header, _keys),
    do: {:error, "expected `kid` in JWT header because provider returned multiple keys"}

  defp validate_required_fields(%{claims: claims}, required_values) do
    Enum.find_value(required_values, :ok, fn key ->
      case Map.has_key?(claims, key) do
        true ->
          nil

        false ->
          claim_keys = claims |> Map.keys() |> Enum.sort() |> inspect()

          {:error, "expected `#{key}` in claims, got: #{claim_keys}"}
      end
    end)
  end

  defp validate_issuer_identifier(%{claims: %{"iss" => iss}}, issuer, config) do
    case iss in [issuer | Keyword.get(config, :trusted_issuers, [])] do
      true -> :ok
      false -> {:error, "expected `iss` in claims to be trusted, got: #{inspect(iss)}"}
    end
  end

  defp validate_audience(%{claims: %{"aud" => [client_id]}}, client_id, _config), do: :ok

  defp validate_audience(%{claims: %{"aud" => auds}}, client_id, config) when is_list(auds) do
    trusted_audiences = [client_id | Keyword.get(config, :trusted_audiences, [])]
    missing_client_id? = client_id not in auds
    untrusted_auds = Enum.filter(auds, &(&1 not in trusted_audiences))

    case {missing_client_id?, untrusted_auds} do
      {false, []} ->
        :ok

      {true, _} ->
        {:error, "expected `aud` in claims to include `:client_id`, got: #{inspect(auds)}"}

      {false, _untrusted_auds} ->
        {:error,
         "expected `aud` in claims to contain only trusted audiences, got: #{inspect(auds)}"}
    end
  end

  defp validate_audience(%{claims: %{"aud" => aud} = claims} = jwt, client_id, config) do
    validate_audience(%{jwt | claims: %{claims | "aud" => [aud]}}, client_id, config)
  end

  defp validate_authorization_party(%{claims: %{"azp" => client_id}}, client_id, _config), do: :ok

  defp validate_authorization_party(%{claims: %{"azp" => azp}}, _client_id, _config) do
    {:error, "expected `azp` in claims to match `:client_id`, got: #{inspect(azp)}"}
  end

  defp validate_authorization_party(_jwt, _client_id, _config), do: :ok

  defp validate_expiration(%{claims: %{"exp" => exp}}) do
    now = :os.system_time(:second)

    case exp > now do
      true -> :ok
      false -> {:error, "expected `exp` in claims to be in the future"}
    end
  end

  defp validate_issued_at(%{claims: %{"iat" => iat}}, config) do
    case Keyword.fetch(config, :id_token_ttl_seconds) do
      :error -> :ok
      {:ok, ttl} -> validate_ttl_reached(iat, ttl)
    end
  end

  defp validate_ttl_reached(iat, ttl) do
    now = :os.system_time(:second)

    case iat + ttl > now do
      true -> :ok
      false -> {:error, "expected `iat` in claims to be no older than #{ttl} seconds"}
    end
  end

  defp validate_nonce(jwt, config) do
    with {:ok, session_params} <- Assent.fetch_config(config, :session_params) do
      validate_for_nonce(session_params, jwt)
    end
  end

  defp validate_for_nonce(%{nonce: stored_nonce}, %{claims: %{"nonce" => provided_nonce}}) do
    case Assent.constant_time_compare(stored_nonce, provided_nonce) do
      true -> :ok
      false -> {:error, "expected `nonce` in claims to match `:nonce` in session params"}
    end
  end

  defp validate_for_nonce(%{nonce: _nonce}, %{claims: claims}) do
    claim_keys = claims |> Map.keys() |> Enum.sort() |> inspect()

    {:error, "expected `nonce` in claims, got: #{claim_keys}"}
  end

  defp validate_for_nonce(_any, %{claims: %{"nonce" => _nonce}}),
    do: {:error, "expected `:nonce` in session params because claims contain `nonce`"}

  defp validate_for_nonce(_any, _jwt), do: :ok

  @doc """
  Fetches claims from userinfo endpoint.

  The userinfo will be fetched from the `userinfo_endpoint` OpenID
  configuration.

  The returned claims will be validated against the `id_token` verifying that
  `sub` is equal.
  """
  @spec fetch_userinfo(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}
  def fetch_userinfo(config, token) do
    with {:ok, openid_config} <- fetch_openid_configuration(config),
         {:ok, id_token} <- fetch_id_token(token),
         {:ok, id_token} <- validate_id_token(config, id_token, openid_config),
         {:ok, userinfo_url} <- fetch_from_openid_config(openid_config, "userinfo_endpoint"),
         {:ok, claims} <- fetch_from_userinfo_endpoint(config, openid_config, token, userinfo_url),
         :ok <- validate_userinfo_sub(id_token.claims, claims) do
      {:ok, claims}
    end
  end

  defp fetch_from_userinfo_endpoint(config, openid_config, token, userinfo_url) do
    case OAuth2.request(config, token, :get, userinfo_url) do
      {:ok, %HTTPResponse{status: 200, body: body, headers: headers}} ->
        maybe_validate_jwt_header(config, openid_config, headers, body)

      {:error, %HTTPResponse{status: 401} = response} ->
        {:error, RequestError.exception(message: "unauthorized token", response: response)}

      {:ok, %HTTPResponse{} = response} ->
        {:error, UnexpectedResponseError.exception(response: response)}

      {:error, %HTTPResponse{} = response} ->
        {:error, InvalidResponseError.exception(response: response)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp maybe_validate_jwt_header(config, openid_config, headers, body) do
    case List.keyfind(headers, "content-type", 0) do
      {"content-type", "application/jwt" <> _rest} -> process_jwt(body, openid_config, config)
      _any -> {:ok, body}
    end
  end

  defp process_jwt(body, openid_config, config) do
    with {:ok, expected_alg} <- Assent.fetch_config(config, :userinfo_signed_response_alg),
         {:ok, client_id} <- Assent.fetch_config(config, :client_id),
         {:ok, issuer} <- fetch_from_openid_config(openid_config, "issuer"),
         {:ok, jwt} <- verify_jwt(body, expected_alg, openid_config, config),
         :ok <- validate_required_fields(jwt, ~w(iss aud)),
         :ok <- validate_issuer_identifier(jwt, issuer, config),
         :ok <- validate_audience(jwt, client_id, config) do
      {:ok, jwt.claims}
    else
      {:error, message} when is_binary(message) ->
        {:error, InvalidUserInfoError.exception(message: message)}

      {:error, message, reason} ->
        {:error, InvalidUserInfoError.exception(message: message, reason: reason)}

      {:error, error} ->
        {:error, error}
    end
  end

  defp validate_userinfo_sub(%{"sub" => sub}, %{"sub" => sub}), do: :ok

  defp validate_userinfo_sub(%{"sub" => _id_token_sub}, %{"sub" => _sub}),
    do:
      {:error,
       InvalidUserInfoError.exception(
         message: "expected `sub` in claims to match `sub` in ID Token"
       )}

  defp validate_userinfo_sub(%{"sub" => _id_token_sub}, claims) do
    claim_keys = claims |> Map.keys() |> Enum.sort() |> inspect()

    {:error,
     InvalidUserInfoError.exception(message: "expected `sub` in claims, got: #{claim_keys}")}
  end
end
