defmodule Assent.Strategy.Google do
  @moduledoc """
  Google OpenID Connect strategy.

  In the normalized user response a `hd` ("Hosted Domain") field is
  included in user parameters and can be used to limit access to users
  belonging to a particular hosted domain.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  To get the refresh token, it's necessary to pass `access_type: "offline"` in
  the authorization request:

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        authorization_params: [
          access_type: "offline",
          scope: "email profile"
        ]
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OIDC.Base

  @impl true
  def default_config(_config) do
    [
      base_url: "https://accounts.google.com/",
      authorization_params: [scope: "email profile"],
      client_authentication_method: "client_secret_post"
    ]
  end
end
