defmodule Assent.Strategy.Auth0 do
  @moduledoc """
  Auth0 OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        domain: "REPLACE_WITH_DOMAIN"
      ]
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.Config

  @spec default_config(Config.t()) :: Keyword.t()
  def default_config(config) do
    append_domain_config(config, [
      authorize_url: "/authorize",
      token_url: "/oauth/token",
      user_url: "/userinfo",
      authorization_params: [scope: "openid profile email"]
    ])
  end

  defp append_domain_config(config, default) do
    case Config.fetch(config, :domain) do
      {:ok, domain} -> Config.put(default, :site, prepend_scheme(domain))
      _error        -> default
    end
  end

  defp prepend_scheme("http" <> _ = domain), do: domain
  defp prepend_scheme(domain), do: "https://" <> domain

  @spec normalize(Config.t(), map()) :: {:ok, map()} | {:error, term()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"        => user["sub"],
      "nickname"   => user["preferred_username"],
      "email"      => user["email"],
      "first_name" => user["given_name"],
      "last_name"  => user["family_name"],
      "name"       => user["name"],
      "image"      => user["picture"],
      "verified"   => user["email_verified"]
    }}
  end
end
