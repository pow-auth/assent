defmodule Assent.Strategy.Twitch do
  @moduledoc """
  Twitch OpenID Connect strategy.

  See `Assent.Strategy.OIDC` for more.
  """
  use Assent.Strategy.OIDC.Base

  @impl true
  def default_config(_config) do
    [
      base_url: "https://id.twitch.tv/oauth2",
      authorization_params: [
        scope: "user:read:email",
        # Only sub is in the ID Token by default so we must specify the
        # additional claims:
        # https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/#requesting-claims
        claims:
          "{\"id_token\":{\"email\":null,\"email_verified\":null,\"picture\":null,\"preferred_username\":null}}"
      ],
      client_authentication_method: "client_secret_post"
    ]
  end
end
