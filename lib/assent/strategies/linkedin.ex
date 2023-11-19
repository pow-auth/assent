defmodule Assent.Strategy.Linkedin do
  @moduledoc """
  Sign In with LinkedIn V2 OpenID Connect Strategy.

  You'll need the `Sign In with LinkedIn v2` product enabled in your app. See the
  [LinkedIn integration guide](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2)
  for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OIDC` for more.
  """

  use Assent.Strategy.OIDC.Base

  @impl true
  def default_config(_config) do
    [
      base_url: "https://www.linkedin.com/oauth",
      authorization_params: [scope: "profile email"],
      client_authentication_method: "client_secret_post"
    ]
  end
end
