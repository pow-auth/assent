defmodule Assent.Strategy.OIDC do
  @moduledoc """
  OpenID Connect strategy.

  This is built upon the `Assent.Strategy.OAuth2` strategy with added OpenID
  Connect capabilities.

  ## Configuration

    - `:client_id` - The client id, required
    - `:site` - The OIDC issuer, required
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
    - `:id_token_ttl_seconds` - The number of seconds from `iat` that an ID
      Token will be considered valid, optional, defaults to nil
    - `:nonce` - The nonce to use for authorization request, optional, MUST be
      session based and unguessable

  See `Assent.Strategy.OAuth2` for more configuration options.

  ## Usage

      config =  [
        client_id: "REPLACE_WITH_CLIENT_ID",
        site: "https://server.example.com",
        authorization_params: [scope: "user:read user:write"]
      ]

      {:ok, {url: url, session_params: session_params}} =
        config
        |> Assent.Config.put(:redirect_uri, "http://localhost:4000/auth/callback")
        |> Assent.Strategy.OIDC.authorize_url()

      {:ok, %{user: user, token: token}} =
        config
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
  alias Assent.{Config, HTTPAdapter.HTTPResponse, RequestError, Strategy.OAuth2}

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
  @spec authorize_url(Config.t()) :: {:ok, %{session_params: %{state: binary()} | %{state: binary(), nonce: binary()}, url: binary()}} | {:error, term()}
  def authorize_url(config) do
    with {:ok, openid_config} <- openid_configuration(config),
         {:ok, authorize_url} <- fetch_from_openid_config(openid_config, "authorization_endpoint"),
         {:ok, params}        <- authorization_params(config) do
      config
      |> Config.put(:authorization_params, params)
      |> Config.put(:authorize_url, authorize_url)
      |> OAuth2.authorize_url()
      |> add_nonce_to_session_params(config)
    end
  end

  defp openid_configuration(config) do
    case Config.get(config, :openid_configuration, nil) do
      nil           -> fetch_openid_configuration(config)
      openid_config -> {:ok, openid_config}
    end
  end

  defp fetch_openid_configuration(config) do
    with {:ok, site} <- Config.fetch(config, :site) do
      configuration_url = Config.get(config, :openid_configuration_uri, "/.well-known/openid-configuration")
      url               = Helpers.to_url(site, configuration_url)

      :get
      |> Helpers.request(url, nil, [], config)
      |> Helpers.decode_response(config)
      |> case do
        {:ok, %HTTPResponse{status: 200, body: configuration}} ->
          {:ok, configuration}

        {:error, response} ->
          {:error, RequestError.invalid(response)}
      end
    end
  end

  defp fetch_from_openid_config(config, key) do
    case Map.fetch(config, key) do
      {:ok, value} -> {:ok, value}
      :error       -> {:error, "`#{key}` not found in OpenID configuration"}
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
    scope     = Config.get(params, :scope, "")
    default   = Config.get(config, :openid_default_scope, "openid")
    new_scope = String.trim(default <> " " <> scope)

    Config.put(params, :scope, new_scope)
  end

  defp add_nonce_param(params, config) do
    case Config.get(config, :nonce, nil) do
      nil   -> params
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

  The userinfo will be fetched from the `userinfo_endpoint` if it exists in the
  OpenID Configuration, otherwise the claims in the ID Token is used.

  The ID Token will be validated per
  [OpenID Connect Core 1.0 rules](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

  See `Assent.Strategy.OAuth2.callback/3` for more.
  """
  @impl true
  @spec callback(Config.t(), map(), atom()) :: {:ok, %{user: map(), token: map()}} | {:error, term()}
  def callback(config, params, strategy \\ __MODULE__) do
    with {:ok, openid_config} <- openid_configuration(config),
         {:ok, method}        <- fetch_client_authentication_method(openid_config, config),
         {:ok, token_url}     <- fetch_from_openid_config(openid_config, "token_endpoint") do

      config
      |> Config.put(:openid_configuration, openid_config)
      |> Config.put(:auth_method, method)
      |> Config.put(:token_url, token_url)
      |> OAuth2.callback(params, strategy)
    end
  end

  defp fetch_client_authentication_method(openid_config, config) do
    method  = Config.get(config, :client_authentication_method, "client_secret_basic")
    methods = Map.get(openid_config, "token_endpoint_auth_methods_supported", ["client_secret_basic"])

    case method in methods do
      true  -> to_client_auth_method(method)
      false -> {:error, "Unsupported client authentication method: #{method}"}
    end
  end

  defp to_client_auth_method("client_secret_basic"), do: {:ok, :client_secret_basic}
  defp to_client_auth_method("client_secret_post"), do: {:ok, :client_secret_post}
  defp to_client_auth_method("client_secret_jwt"), do: {:ok, :client_secret_jwt}
  defp to_client_auth_method("private_key_jwt"), do: {:ok, :private_key_jwt}
  defp to_client_auth_method(method), do: {:error, "Invalid client authentication method: #{method}"}

  @doc false
  @spec get_user(Config.t(), map()) :: {:ok, map()} | {:error, term()}
  def get_user(config, token) do
    with {:ok, openid_config} <- Config.fetch(config, :openid_configuration),
         {:ok, jwt}           <- validate_id_token(config, token["id_token"]) do
      fetch_and_normalize_userinfo(openid_config, config, token, jwt.claims)
    end
  end

  @spec validate_id_token(Config.t(), binary()) :: {:ok, map()} | {:error, term()}
  def validate_id_token(config, token) do
    with {:ok, openid_config} <- Config.fetch(config, :openid_configuration),
         {:ok, header}        <- peek_header(token, config),
         {:ok, client_id}     <- Config.fetch(config, :client_id),
         {:ok, issuer}        <- fetch_from_openid_config(openid_config, "issuer"),
         {:ok, secret_or_key} <- fetch_secret(header, openid_config, config),
         {:ok, jwt}           <- Helpers.verify_jwt(token, secret_or_key, config),
         :ok                  <- validate_issuer_identifer(jwt, issuer),
         :ok                  <- validate_audience(jwt, client_id),
         :ok                  <- validate_alg(jwt, openid_config),
         :ok                  <- validate_verified(jwt),
         :ok                  <- validate_expiration(jwt),
         :ok                  <- validate_issued_at(jwt, config),
         :ok                  <- validate_nonce(jwt, config) do
      {:ok, jwt}
    end
  end

  defp peek_header(encoded, config) do
    with [header, _, _] <- String.split(encoded, "."),
         {:ok, json}    <- Base.url_decode64(header, padding: false) do
      Config.json_library(config).decode(json)
    else
      {:error, error} -> {:error, error}
      _any            -> {:error, "The ID Token is not a valid JWT"}
    end
  end

  defp fetch_secret(%{"alg" => "none"}, _openid_config, _config), do: {:ok, nil}
  defp fetch_secret(%{"alg" => "HS" <> _rest}, _openid_config, config) do
    Config.fetch(config, :client_secret)
  end
  defp fetch_secret(header, openid_config, config) do
    with {:ok, jwks_uri} <- fetch_from_openid_config(openid_config, "jwks_uri"),
         {:ok, keys}     <- fetch_public_keys(jwks_uri, config) do
      find_key(header, keys)
    end
  end

  defp fetch_public_keys(uri, config) do
    :get
    |> Helpers.request(uri, nil, [], config)
    |> Helpers.decode_response(config)
    |> case do
      {:ok, %HTTPResponse{status: 200, body: %{"keys" => keys}}} ->
        {:ok, keys}

      {:ok, _any} ->
        {:ok, []}

      {:error, response} ->
        {:error, RequestError.invalid(response)}
    end
  end

  defp find_key(%{"kid" => kid}, [%{"kid" => kid} = key | _keys]), do: {:ok, key}
  defp find_key(%{"kid" => _kid} = header, [%{"kid" => _other} | keys]), do: find_key(header, keys)
  defp find_key(%{"kid" => kid}, []), do: {:error, "No keys found for the `kid` value \"#{kid}\" provided in ID Token"}
  defp find_key(_header, []), do: {:error, "No keys found in `jwks_uri` provider configuration"}
  defp find_key(_header, [key]), do: {:ok, key}
  defp find_key(_header, _keys), do: {:error, "Multiple public keys found in provider configuration and no `kid` value in ID Token"}

  defp validate_issuer_identifer(%{claims: %{"iss" => iss}}, iss), do: :ok
  defp validate_issuer_identifer(%{claims: %{"iss" => iss}}, _iss), do: {:error, "Invalid issuer \"#{iss}\" in ID Token"}

  defp validate_audience(%{claims: %{"aud" => aud}}, aud), do: :ok
  defp validate_audience(%{claims: %{"aud" => aud}}, _client_id), do: {:error, "Invalid audience \"#{aud}\" in ID Token"}

  defp validate_alg(%{header: %{"alg" => alg}}, %{"id_token_signed_response_alg" => algs}) do
    case alg in algs do
      true  -> :ok
      false -> {:error, "Unsupported algorithm \"#{alg}\" in ID Token"}
    end
  end
  defp validate_alg(%{header: %{"alg" => "RS256"}}, _openid_config), do: :ok
  defp validate_alg(%{header: %{"alg" => _alg}}, _openid_config), do: {:error, "`alg` in ID Token can only be \"RS256\""}

  defp validate_verified(%{verified?: true}), do: :ok
  defp validate_verified(%{verified?: false}), do: {:error, "Invalid JWT signature for ID Token"}

  defp validate_expiration(%{claims: %{"exp" => exp}}) do
    now = :os.system_time(:second)

    case exp > now do
      true  -> :ok
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
      true  -> :ok
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

  defp fetch_and_normalize_userinfo(openid_config, config, token, claims) do
    openid_config
    |> fetch_from_openid_config("userinfo_endpoint")
    |> case do
      {:ok, user_url} -> fetch_from_userinfo_endpoint(config, token, user_url)
      {:error, _any}  -> {:ok, claims}
    end
    |> normalize()
  end

  defp fetch_from_userinfo_endpoint(config, token, user_url) do
    config
    |> Config.put(:user_url, user_url)
    |> OAuth2.get_user(token)
  end

  defp normalize({:ok, user}), do: Helpers.normalize_userinfo(user)
  defp normalize({:error, error}), do: {:error, error}
end
