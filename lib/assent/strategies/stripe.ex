defmodule Assent.Strategy.Stripe do
  @moduledoc """
  Stripe OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OAuth2.Base

  @impl true
  def default_config(_config) do
    [
      site: "https://connect.stripe.com",
      user_url: "https://api.stripe.com/v1/accounts",
      auth_method: :client_secret_post
    ]

  end

  @impl true
  def normalize(_config, user) do
    {:ok, %{
      "sub"            => user["id"],
      "name"           => Map.get(user, "business_profile", %{})["name"],
      "email"          => user["email"],
      "website"        => Map.get(user, "business_profile", %{})["url"]
    }}
  end
end
