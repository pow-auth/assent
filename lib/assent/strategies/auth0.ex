defmodule Assent.Strategy.Auth0 do
  @moduledoc """
  Auth0 OpenID Connect strategy.

  ## Configuration

  - `:base_url` - The Auth0 base URL, required

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        base_url: "https://my-domain.auth0.com",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OIDC.Base

  @impl true
  def default_config(_config) do
    [
      authorization_params: [scope: "email profile"],
      client_authentication_method: "client_secret_post"
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok, updated_at, 0} = DateTime.from_iso8601(user["updated_at"])

    {:ok,
     %{
       user
       | "updated_at" => DateTime.to_unix(updated_at)
     }}
  end
end
