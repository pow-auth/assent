defmodule Assent.Strategy.Gitlab do
  @moduledoc """
  Gitlab OpenID Connect strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OIDC.Base

  @impl true
  def default_config(_config) do
    [
      base_url: "https://gitlab.com",
      authorization_params: [scope: "email profile"],
      client_authentication_method: "client_secret_post"
    ]
  end
end
