defmodule Assent.Strategy.Auth0 do
  @moduledoc """
  Auth0 OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        base_url: "https://my-domain.auth0.com",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OAuth2.Base

  @impl true
  def default_config(config) do
    append_domain_config(config,
      authorize_url: "/authorize",
      token_url: "/oauth/token",
      user_url: "/userinfo",
      authorization_params: [scope: "openid profile email"],
      auth_method: :client_secret_post
    )
  end

  defp append_domain_config(config, default) do
    case Assent.fetch_config(config, :domain) do
      {:ok, domain} ->
        IO.warn("`:domain` config is deprecated. Use `:base_url` instead.")
        Keyword.put(default, :base_url, prepend_scheme(domain))

      _error ->
        default
    end
  end

  defp prepend_scheme("http" <> _ = domain), do: domain
  defp prepend_scheme(domain), do: "https://" <> domain

  @impl true
  def normalize(_config, user), do: {:ok, user}
end
