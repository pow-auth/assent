defmodule Assent.Strategy.DigitalOcean do
  @moduledoc """
  DigitalOcean OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """

  use Assent.Strategy.OAuth2.Base
  alias Assent.Config

  @impl true
  def default_config(config) do
    [
      base_url: "https://api.digitalocean.com",
      authorize_url: "https://cloud.digitalocean.com/v1/oauth/authorize",
      token_url: "https://cloud.digitalocean.com/v1/oauth/token",
      user_url: "/v2/account",
      authorization_params: [
        prompt: Config.get(config, :prompt, "select_account"),
        scope: "read write",
        response_type: "code"
      ],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, %{"account" => user}) do
    {:ok,
     %{
       "sub" => user["uuid"],
       "email" => user["email"],
       "email_verified" => user["email_verified"]
     }}
  end
end
