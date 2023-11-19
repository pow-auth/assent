defmodule Assent.Strategy.OIDC do
  @moduledoc """
  OpenID Connect strategy.

  This is built upon the `Assent.Strategy.OAuth2` strategy with added OpenID
  Connect capabilities.

  ## Configuration

    - `:client_id` - The client id, required
    - `:base_url` - The OIDC issuer, required
    - `:openid_configuration_uri` - The URI for OpenID Provider, optional,
      defaults to `/.well-known/openid-configuration`
    - `:client_authentication_method` - The Client Authentication method to
      use, optional, defaults to `client_secret_basic`
    - `:client_secret` - The client secret, required if
      `:client_authentication_method` is `:client_secret_basic`,
      `:client_secret_post`, or `:client_secret_jwt`
    - `:openid_configuration` - The OpenID configuration, optional, the
      configuration will be fetched from `:openid_configuration_uri` if this is
      not defined
    - `:id_token_signed_response_alg` - The `id_token_signed_response_alg`
      parameter sent by the Client during Registration, defaults to `RS256`
    - `:id_token_ttl_seconds` - The number of seconds from `iat` that an ID
      Token will be considered valid, optional, defaults to nil
    - `:nonce` - The nonce to use for authorization request, optional, MUST be
      session based and unguessable
    - `:trusted_audiences` - A list of audiences that are trusted, optional.

  See `Assent.Strategy.OAuth2` for more configuration options.

  ## Usage

      config =  [
        client_id: "REPLACE_WITH_CLIENT_ID",
        base_url: "https://server.example.com",
        authorization_params: [scope: "user:read user:write"]
      ]

      {:ok, {url: url, session_params: session_params}} =
        config
        |> Assent.Config.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> Assent.Strategy.OIDC.authorize_url()

      {:ok, %{user: user, token: token}} =
        config
        |> Assent.Config.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> Assent.Config.put(:session_params, session_params)
        |> Assent.Strategy.OIDC.callback(params)

  ## Nonce

  `:nonce` can be set in the provider config. The `:nonce` will be returned in
  the `:session_params` along with `:state`. You can use this to store the value
  in the current session e.g. a httpOnly session cookie.

  A random value generator can look like this:

      16
      |> :crypto.strong_rand_bytes()
      |> Base.encode64(padding: false)

  PowAssent will dynamically generate one for the session if `:nonce` is set to
  `true`.

  See `Assent.Strategy.OIDC.authorize_url/1` for more.
  """
  @behaviour Assent.Strategy

  alias Assent.Strategy, as: Helpers

  alias Assent.{
    Config,
    HTTPAdapter.HTTPResponse,
    InvalidResponseError,
    RequestError,
    Strategy.OAuth2,
    UnexpectedResponseError
  }

  @doc """
  Generates an authorization URL for request phase.

  The authorization url will be fetched from the OpenID configuration URI.

  `openid` will automatically be added to the `:scope` in
  `:authorization_params`, unless `:openid_default_scope` has been set.

  Add `:nonce` to the config to pass it with the authorization request. The
  nonce will be returned in `:session_params`. The nonce MUST be session based
  and unguessable. A cryptographic hash of a cryptographically random value
  could be stored in a httpOnly session cookie.

  See `Assent.Strategy.OAuth2.authorize_url/1` for more.
  """
  @impl true
  @spec authorize_url(Config.t()) ::
          {:ok,
           %{
             session_params: %{state: binary()} | %{state: binary(), nonce: binary()},
             url: binary()
           }}
          | {:error, term()}
  def authorize_url(config) do
    with {:ok, openid_config} <- openid_configuration(config),
         {:ok, authorize_url} <-
           fetch_from_openid_config(openid_config, "authorization_endpoint"),
         {:ok, params} <- authorization_params(config) do
      config
      |> Config.put(:authorization_params, params)
      |> Config.put(:authorize_url, authorize_url)
      |> OAuth2.authorize_url()
      |> add_nonce_to_session_params(config)
    end
  end

  defp openid_configuration(config) do
    case Config.get(config, :openid_configuration, nil) do
      nil -> fetch_openid_configuration(config)
      openid_config -> {:ok, openid_config}
    end
  end

  defp fetch_openid_configuration(config) do
    with {:ok, base_url} <- Config.__base_url__(config) do
      configuration_url =
        Config.get(config, :openid_configuration_uri, "/.well-known/openid-configuration")

      url = Helpers.to_url(base_url, configuration_url)

      :get
      |> Helpers.request(url, nil, [], config)
      |> process_openid_configuration_response()
    end
  end

  defp process_openid_configuration_response(
         {:ok, %HTTPResponse{status: 200, body: configuration}}
       ) do
    {:ok, configuration}
  end

  defp process_openid_configuration_response(any), do: process_response(any)

  defp process_response({:ok, %HTTPResponse{} = response}),
    do: {:error, UnexpectedResponseError.exception(response: response)}

  defp process_response({:error, %HTTPResponse{} = response}),
    do: {:error, InvalidResponseError.exception(response: response)}

  defp process_response({:error, error}), do: {:error, error}

  defp fetch_from_openid_config(config, key) do
    case Map.fetch(config, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, "`#{key}` not found in OpenID configuration"}
    end
  end

  defp authorization_params(config) do
    new_params =
      config
      |> Config.get(:authorization_params, [])
      |> add_default_scope_param(config)
      |> add_nonce_param(config)

    {:ok, new_params}
  end

  defp add_default_scope_param(params, config) do
    scope = Config.get(params, :scope, "")
    default = Config.get(config, :openid_default_scope, "openid")
    new_scope = String.trim(default <> " " <> scope)

    Config.put(params, :scope, new_scope)
  end

  defp add_nonce_param(params, config) do
    case Config.get(config, :nonce, nil) do
      nil -> params
      nonce -> Config.put(params, :nonce, nonce)
    end
  end

  defp add_nonce_to_session_params({:ok, resp}, config) do
    case Config.get(config, :nonce, nil) do
      nil ->
        {:ok, resp}

      nonce ->
        session_params =
          resp
          |> Map.get(:session_params, %{})
          |> Map.put(:nonce, nonce)

        {:ok, Map.put(resp, :session_params, session_params)}
    end
  end

  defp add_nonce_to_session_params({:error, error}, _config),
    do: {:error, error}

  @doc """
  Callback phase for generating access token and fetch user data.

  The token url will be fetched from the OpenID configuration URI.

  If the returned ID Token is signed with a symmetric key, `:client_secret`
  will be required and used to verify the ID Token. If it was signed with a
  private key, the appropriate public key will be fetched from the `jwks_uri`
  setting in the OpenID configuration to verify the ID Token.

  The ID Token will be validated per
  [OpenID Connect Core 1.0 rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

  See `Assent.Strategy.OAuth2.callback/3` for more.
  """
  @impl true
  @spec callback(Config.t(), map(), atom()) ::
          {:ok, %{user: map(), token: map()}} | {:error, term()}
  def callback(config, params, strategy \\ __MODULE__) do
    with {:ok, openid_config} <- openid_configuration(config),
         {:ok, method} <- fetch_client_authentication_method(openid_config, config),
         {:ok, token_url} <- fetch_from_openid_config(openid_config, "token_endpoint") do
      config
      |> Config.put(:openid_configuration, openid_config)
      |> Config.put(:auth_method, method)
      |> Config.put(:token_url, token_url)
      |> OAuth2.callback(params, strategy)
    end
  end

  defp fetch_client_authentication_method(openid_config, config) do
    method = Config.get(config, :client_authentication_method, "client_secret_basic")
    methods = Map.get(openid_config, "token_endpoint_auth_methods_supported")

    supported_method? = if is_nil(methods), do: true, else: method in methods

    case supported_method? do
      true -> to_client_auth_method(method)
      false -> {:error, "Unsupported client authentication method: #{method}"}
    end
  end

  defp to_client_auth_method("client_secret_basic"), do: {:ok, :client_secret_basic}
  defp to_client_auth_method("client_secret_post"), do: {:ok, :client_secret_post}
  defp to_client_auth_method("client_secret_jwt"), do: {:ok, :client_secret_jwt}
  defp to_client_auth_method("private_key_jwt"), do: {:ok, :private_key_jwt}

  defp to_client_auth_method(method),
    do: {:error, "Invalid client authentication method: #{method}"}

  # https://openid.net/specs/draft-jones-json-web-token-07.html#ReservedClaimName
  @reserved_jwt_names ~w(exp nbf iat iss aud prn jti typ)

  # https://openid.net/specs/openid-connect-core-1_0.html#IDToken
  @id_token_names ~w(iss sub aud exp iat auth_time nonce acr amr azp at_hash c_hash sub_jwk)

  # All ID Token claim names to be excluded from the user params
  @id_token_names_to_exclude Enum.uniq(@reserved_jwt_names ++ (@id_token_names -- ~w(sub)))

  @doc """
  Fetches user params from ID token.

  The ID Token is validated, and the claims is returned as the user params.
  Use `fetch_userinfo/2` to fetch the claims from the `userinfo` endpoint.
  """
  @spec fetch_user(Config.t(), map()) :: {:ok, map()} | {:error, term()}
  def fetch_user(config, token) do
    with {:ok, id_token} <- fetch_id_token(token),
         {:ok, jwt} <- validate_id_token(config, id_token) do
      {:ok, Map.drop(jwt.claims, @id_token_names_to_exclude)}
    end
  end

  defp fetch_id_token(token) do
    case Map.fetch(token, "id_token") do
      {:ok, id_token} ->
        {:ok, id_token}

      :error ->
        {:error,
         "The `id_token` key not found in token params, only found these keys: #{Enum.join(Map.keys(token), ", ")}"}
    end
  end

  @doc """
  Validates the ID token.

  The OpenID configuration will be dynamically fetched if not set in the
  config.

  The ID Token will be validated per
  [OpenID Connect Core 1.0 rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
  """
  @spec validate_id_token(Config.t(), binary()) :: {:ok, map()} | {:error, term()}
  def validate_id_token(config, id_token) do
    expected_alg = Config.get(config, :id_token_signed_response_alg, "RS256")

    with {:ok, openid_config} <- openid_configuration(config),
         {:ok, client_id} <- Config.fetch(config, :client_id),
         {:ok, issuer} <- fetch_from_openid_config(openid_config, "issuer"),
         {:ok, jwt} <- verify_jwt(id_token, openid_config, config),
         :ok <- validate_required_fields(jwt),
         :ok <- validate_issuer_identifier(jwt, issuer),
         :ok <- validate_audience(jwt, client_id, config),
         :ok <- validate_authorization_party(jwt, client_id, config),
         :ok <- validate_alg(jwt, expected_alg),
         :ok <- validate_verified(jwt),
         :ok <- validate_expiration(jwt),
         :ok <- validate_issued_at(jwt, config),
         :ok <- validate_nonce(jwt, config) do
      {:ok, jwt}
    end
  end

  defp verify_jwt(token, openid_config, config) do
    with {:ok, header} <- peek_header(token, config),
         {:ok, secret_or_key} <- fetch_secret(header, openid_config, config) do
      Helpers.verify_jwt(token, secret_or_key, config)
    end
  end

  defp peek_header(encoded, config) do
    with [header, _, _] <- String.split(encoded, "."),
         {:ok, json} <- Base.url_decode64(header, padding: false) do
      Config.json_library(config).decode(json)
    else
      {:error, error} -> {:error, error}
      _any -> {:error, "The ID Token is not a valid JWT"}
    end
  end

  defp fetch_secret(%{"alg" => "none"}, _openid_config, _config), do: {:ok, ""}

  defp fetch_secret(%{"alg" => "HS" <> _rest}, _openid_config, config) do
    Config.fetch(config, :client_secret)
  end

  defp fetch_secret(header, openid_config, config) do
    with {:ok, jwks_uri} <- fetch_from_openid_config(openid_config, "jwks_uri"),
         {:ok, keys} <- fetch_public_keys(jwks_uri, config) do
      find_key(header, keys)
    end
  end

  defp fetch_public_keys(uri, config) do
    :get
    |> Helpers.request(uri, nil, [], config)
    |> process_public_keys_response()
  end

  defp process_public_keys_response({:ok, %HTTPResponse{status: 200, body: %{"keys" => keys}}}),
    do: {:ok, keys}

  defp process_public_keys_response({:ok, %HTTPResponse{status: 200}}), do: {:ok, []}
  defp process_public_keys_response(any), do: process_response(any)

  defp find_key(%{"kid" => kid}, [%{"kid" => kid} = key | _keys]), do: {:ok, key}

  defp find_key(%{"kid" => _kid} = header, [%{"kid" => _other} | keys]),
    do: find_key(header, keys)

  defp find_key(%{"kid" => kid}, []),
    do: {:error, "No keys found for the `kid` value \"#{kid}\" provided in ID Token"}

  defp find_key(_header, []), do: {:error, "No keys found in `jwks_uri` provider configuration"}
  defp find_key(_header, [key]), do: {:ok, key}

  defp find_key(_header, _keys) do
    {:error,
     "Multiple public keys found in provider configuration and no `kid` value in ID Token"}
  end

  defp validate_required_fields(%{claims: claims}) do
    Enum.find_value(~w(iss sub aud exp iat), :ok, fn key ->
      case Map.has_key?(claims, key) do
        true -> nil
        false -> {:error, "Missing `#{key}` in ID Token claims"}
      end
    end)
  end

  defp validate_issuer_identifier(%{claims: %{"iss" => iss}}, iss), do: :ok

  defp validate_issuer_identifier(%{claims: %{"iss" => iss}}, _iss),
    do: {:error, "Invalid issuer \"#{iss}\" in ID Token"}

  defp validate_audience(%{claims: %{"aud" => aud} = claims} = jwt, client_id, config)
       when is_binary(aud) do
    validate_audience(%{jwt | claims: %{claims | "aud" => [aud]}}, client_id, config)
  end

  defp validate_audience(%{claims: %{"aud" => [client_id]}}, client_id, _config), do: :ok

  defp validate_audience(%{claims: %{"aud" => auds}}, client_id, config) do
    trusted_audiences = Config.get(config, :trusted_audiences, []) ++ [client_id]
    missing_client_id? = client_id not in auds
    untrusted_auds = Enum.filter(auds, &(&1 not in trusted_audiences))

    case {missing_client_id?, untrusted_auds} do
      {false, []} ->
        :ok

      {true, _} ->
        {:error, "`:client_id` not in audience #{inspect(auds)} in ID Token"}

      {false, untrusted_auds} ->
        {:error, "Untrusted audience(s) #{inspect(untrusted_auds)} in ID Token"}
    end
  end

  defp validate_authorization_party(%{claims: %{"azp" => client_id}}, client_id, _config), do: :ok

  defp validate_authorization_party(%{claims: %{"azp" => azp}}, _client_id, _config) do
    {:error, "Invalid authorized party \"#{azp}\" in ID Token"}
  end

  defp validate_authorization_party(_jwt, _client_id, _config), do: :ok

  defp validate_alg(%{header: %{"alg" => alg}}, alg), do: :ok

  defp validate_alg(%{header: %{"alg" => alg}}, expected_alg),
    do: {:error, "Expected `alg` in ID Token to be \"#{expected_alg}\", got \"#{alg}\""}

  defp validate_verified(%{verified?: true}), do: :ok
  defp validate_verified(%{verified?: false}), do: {:error, "Invalid JWT signature for ID Token"}

  defp validate_expiration(%{claims: %{"exp" => exp}}) do
    now = :os.system_time(:second)

    case exp > now do
      true -> :ok
      false -> {:error, "The ID Token has expired"}
    end
  end

  defp validate_issued_at(%{claims: %{"iat" => iat}}, config) do
    case Config.get(config, :id_token_ttl_seconds, nil) do
      nil -> :ok
      ttl -> validate_ttl_reached(iat, ttl)
    end
  end

  defp validate_ttl_reached(iat, ttl) do
    now = :os.system_time(:second)

    case iat + ttl > now do
      true -> :ok
      false -> {:error, "The ID Token was issued too long ago"}
    end
  end

  defp validate_nonce(jwt, config) do
    with {:ok, session_params} <- Config.fetch(config, :session_params) do
      validate_for_nonce(session_params, jwt)
    end
  end

  defp validate_for_nonce(%{nonce: stored_nonce}, %{claims: %{"nonce" => provided_nonce}}) do
    case Assent.constant_time_compare(stored_nonce, provided_nonce) do
      true -> :ok
      false -> {:error, "Invalid `nonce` included in ID Token"}
    end
  end

  defp validate_for_nonce(%{nonce: _nonce}, _jwt),
    do: {:error, "`nonce` is not included in ID Token"}

  defp validate_for_nonce(_any, %{claims: %{"nonce" => _nonce}}),
    do: {:error, "`nonce` included in ID Token but doesn't exist in session params"}

  defp validate_for_nonce(_any, _jwt), do: :ok

  @doc """
  Fetches claims from userinfo endpoint.

  The userinfo will be fetched from the `userinfo_endpoint` OpenID
  configuration.

  The returned claims will be validated against the `id_token` verifying that
  `sub` is equal.
  """
  @spec fetch_userinfo(Config.t(), map()) :: {:ok, map()} | {:error, term()}
  def fetch_userinfo(config, token) do
    with {:ok, openid_config} <- openid_configuration(config),
         {:ok, userinfo_url} <- fetch_from_openid_config(openid_config, "userinfo_endpoint"),
         {:ok, claims} <-
           fetch_from_userinfo_endpoint(config, openid_config, token, userinfo_url),
         :ok <- validate_userinfo_sub(config, token["id_token"], claims) do
      {:ok, claims}
    end
  end

  defp fetch_from_userinfo_endpoint(config, openid_config, token, userinfo_url) do
    config
    |> OAuth2.request(token, :get, userinfo_url)
    |> process_userinfo_response(openid_config, config)
  end

  defp process_userinfo_response(
         {:ok, %HTTPResponse{status: 200, body: body, headers: headers}},
         openid_config,
         config
       ) do
    case List.keyfind(headers, "content-type", 0) do
      {"content-type", "application/jwt" <> _rest} -> process_jwt(body, openid_config, config)
      _any -> {:ok, body}
    end
  end

  defp process_userinfo_response(
         {:error, %HTTPResponse{status: 401} = response},
         _openid_config,
         _config
       ) do
    {:error, RequestError.exception(message: "Unauthorized token", response: response)}
  end

  defp process_userinfo_response(any, _openid_config, _config), do: process_response(any)

  defp process_jwt(body, openid_config, config) do
    with {:ok, jwt} <- verify_jwt(body, openid_config, config),
         :ok <- validate_verified(jwt) do
      {:ok, jwt.claims}
    end
  end

  defp validate_userinfo_sub(config, id_token, claims) when is_binary(id_token) do
    with {:ok, jwt} <- validate_id_token(config, id_token) do
      validate_userinfo_sub(config, jwt.claims, claims)
    end
  end

  defp validate_userinfo_sub(_config, %{"sub" => sub}, %{"sub" => sub}), do: :ok

  defp validate_userinfo_sub(_config, %{"sub" => _sub_1}, %{"sub" => _sub_2}),
    do: {:error, "`sub` in userinfo response not the same as in ID Token"}

  defp validate_userinfo_sub(_config, %{"sub" => _sub}, _claims),
    do: {:error, "`sub` not in userinfo response"}
end
