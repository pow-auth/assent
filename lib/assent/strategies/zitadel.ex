defmodule Assent.Strategy.Zitadel do
  @moduledoc """
  Zitadel Sign In OIDC strategy.

  ## Usage

  ### Required configuration parameters
      config = [
        base_url: ""
        client_id: "REPLACE_WITH_CLIENT_ID",
        redirect_uri: "http://localhost:4000/auth/callback",
        response_type: one of code, id_token token, id_token,
        scope: openid is required other options [email, profile]
        code_challenge:	The SHA-256 value of the generated code_verifier,
        code_challenge_method: "S256"
      ]
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.{Config, Strategy.OIDC.Base}

  @impl true
  def default_config(config) do
    {:ok, base_url} = Config.fetch(config, :base_url)
    {:ok, issuer} = Config.fetch(config, :issuer)

    [
      base_url: base_url,
      openid_configuration: %{
        "issuer" => issuer,
        "authorization_endpoint" => base_url <> "/oauth/v2/authorize",
        "token_endpoint" => base_url <> "/oauth/v2/token",
        "jwks_uri" => base_url <> "/oauth/v2/keys",
        "token_endpoint_auth_methods_supported" => ["none"]
      },
      authorization_params: [scope: "email", response_type: "code"],
      client_authentication_method: "none",
      openid_default_scope: "openid"
    ]
  end

  @doc false
  @impl true
  def callback(config, params) do
    config
    |> Base.callback(params, __MODULE__)
  end

  # @impl true
  # def fetch_user(config, token) do
  #  with {:ok, user} <- OIDC.fetch_user(config, token),
  #       {:ok, user_info} <- Config.fetch(config, :user) do
  #    {:ok, Map.merge(user, user_info)}
  #  end
  # end

  # @impl true
  # def normalize(_config, user) do
  #  {:ok,
  #   %{
  #     "sub" => user["sub"],
  #     "email" => user["email"],
  #     "email_verified" => true,
  #     "given_name" => Map.get(user, "name", %{})["firstName"],
  #     "family_name" => Map.get(user, "name", %{})["lastName"],
  #     "roles" => Map.get(user["profile"], "urn:zitadel:iam:org:project:roles")
  #   }}
  # end
end
