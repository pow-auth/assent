defmodule Assent.Strategy.Stripe do
  @moduledoc """
  Stripe Connect OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.

  ## Connect Express

  This strategy uses Connect Standard by default. To use Connect Express, the
  following config can be used:


      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        authorize_url: "https://connect.stripe.com/express/oauth/authorize"
        # authorization_params: [
        #   stripe_user: [business_type: "company", email: "user@example.com"],
        #   suggested_capabilities: ["transfers"]
        # ]
      ]

  """
  use Assent.Strategy.OAuth2.Base

  @impl true
  def default_config(_config) do
    [
      base_url: "https://api.stripe.com/",
      authorize_url: "https://connect.stripe.com/oauth/authorize",
      token_url: "https://connect.stripe.com/oauth/token",
      user_url: "/v1/account",
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "email" => user["email"]
     }}
  end
end
