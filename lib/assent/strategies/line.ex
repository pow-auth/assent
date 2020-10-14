defmodule Assent.Strategy.LINE do
  @moduledoc """
  LINE Login OpenID Connect Strategy.

  See `Assent.Strategy.OIDC` for more.
  """

  use Assent.Strategy.OIDC.Base

  @impl true
  def default_config(_config) do
    [
      site: "https://access.line.me",
      authorization_params: [scope: "email profile", response_type: "code"],
      openid_configuration: %{
        "id_token_signed_response_alg" => ["HS256"],
        "issuer" => "https://access.line.me",
        "authorization_endpoint" => "https://access.line.me/oauth2/v2.1/authorize",
        "token_endpoint" => "https://api.line.me/oauth2/v2.1/token",
        "jwks_uri" => "https://api.line.me/oauth2/v2.1/certs",
        "response_types_supported" => ["code"],
        "subject_types_supported" => ["pairwise"],
        "id_token_signing_alg_values_supported" => ["ES256"]
      }
    ]
  end

  @impl true
  def normalize(_config, user), do: {:ok, user}
end
