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
        code_challenge:	The SHA-256 value of the generated code_verifier,
        code_challenge_method: "S256",
        onboard: use Zitadel form to onboard users, true | false if true scope must include `urn:zitadel:iam:org:id:{id}`
      ]
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.{Config, Strategy.OIDC.Base}

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
      value -> list ++ {config_key, value}
    end
  end
end
