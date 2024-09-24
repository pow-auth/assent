defmodule Assent.Strategy.Zitadel do
  @moduledoc """
  Zitadel Sign In OIDC strategy.

  ## Needed settings

  Zitadel reccommended authentication implementation is OIDC with PKCE.
  This means we need to add PKCE management in Oauth2 strategy and also
  `code_verifier` management in Oidc strategy.

  I added a `none` `client_authentication_method` as per zitadel 
  authentication method configuration which maps to auth_method nil.

  I also added a resource_id parameter which is needed in Oidc strategy,
  the Zitadel resource id is the id of the project, it is added by default
  in the token `auds` and must be added in the trusted sources to avoid 
  `Untrusted audiences` error.

  ## Usage

  ### Required configuration parameters
      config = [
        base_url: ""
        issuer: should be same of base url
        client_id: "REPLACE_WITH_CLIENT_ID",
        resource_id: "REPLACE_WITH_RESOURCE_ID",
        redirect_uri: "http://localhost:4000/auth/callback",
        response_type: one of code, id_token token, id_token,
        scope: openid is required other options [email, profile]
        client_authentication_method: can use special :private_key_jwt_zitadel
        code_challenge:	The SHA-256 value of the generated code_verifier,
        code_challenge_method: "S256",
        onboard: use Zitadel form to onboard users, true | false if true scope must include `urn:zitadel:iam:org:id:{id}`
      ]
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.Strategy, as: Helpers

  alias Assent.{
    Config,
    Strategy.OIDC.Base,
    HTTPAdapter.HTTPResponse,
    InvalidResponseError,
    UnexpectedResponseError
  }

  @impl true
  def default_config(config) do
    {:ok, base_url} = Config.fetch(config, :base_url)
    {:ok, issuer} = Config.fetch(config, :issuer)

    if is_nil(issuer) do
      {:error, Assent.Config.MissingKeyError.exception(key: "issuer")}
    end

    client_authentication_method =
      Config.get(config, :client_authentication_method, "none")

    authorization_params =
      [response_type: "code"]
      |> maybe_add(:scope, config)
      |> maybe_add(:prompt, config)

    [
      base_url: base_url,
      openid_configuration: %{
        "issuer" => issuer,
        "authorization_endpoint" => base_url <> "/oauth/v2/authorize",
        "token_endpoint" => base_url <> "/oauth/v2/token",
        "jwks_uri" => base_url <> "/oauth/v2/keys",
        "token_endpoint_auth_methods_supported" => ["none"]
      },
      authorization_params: authorization_params,
      client_authentication_method: client_authentication_method,
      openid_default_scope: "openid"
    ]
  end

  @doc false
  @impl true
  def callback(config, params) do
    config
    |> Base.callback(params, __MODULE__)
  end

  defp maybe_add(list, config_key, config) do
    case Config.get(config, config_key, nil) do
      nil -> list
      value -> list ++ [{config_key, value}]
    end
  end

  @doc """
  Authenticates a zitadel api with JWT
  """
  @spec authenticate_api(Config.t()) :: {:ok, map()} | {:error, term()}
  def authenticate_api(config) do
    token_url = Config.get(config, :token_url, "/oauth/v2/token")

    with {:ok, base_url} <- Config.__base_url__(config),
         {:ok, auth_headers, params} <- jwt_authentication_params(config) do
      headers = [{"content-type", "application/x-www-form-urlencoded"}] ++ auth_headers
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

  defp jwt_authentication_params(config) do
    with {:ok, token} <- gen_client_secret(config) do
      headers = []

      body = [
        scope: "openid",
        assertion: token,
        grant_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      ]

      {:ok, headers, body}
    end
  end

  @jwt_expiration_seconds 3600

  defp gen_client_secret(config) do
    timestamp = :os.system_time(:second)

    config =
      config
      |> default_config()
      |> Keyword.merge(config)

    with {:ok, base_url} <- Config.fetch(config, :base_url),
         {:ok, client_id} <- Config.fetch(config, :client_id),
         {:ok, _private_key_id} <- Config.fetch(config, :private_key_id),
         {:ok, private_key} <- Config.fetch(config, :private_key) do
      claims = %{
        "aud" => base_url,
        "iss" => client_id,
        "sub" => client_id,
        "iat" => timestamp,
        "exp" => timestamp + @jwt_expiration_seconds
      }

      Helpers.sign_jwt(claims, "RS256", private_key, config)
    end
  end
end
