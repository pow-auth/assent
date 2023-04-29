defmodule Assent.Strategy.Linkedin do
  @moduledoc """
  Sign In with LinkedIn v2 OpenID Connect Strategy.

  See `Assent.Strategy.OIDC` for more.
  """

  use Assent.Strategy.OIDC.Base

  @impl true
  def default_config(_config) do
    [
      site: "https://www.linkedin.com/oauth",
      authorization_params: [scope: "r_emailaddress r_liteprofile"],
      client_authentication_method: "client_secret_post",
      openid_default_scope: ""
    ]
  end
end
