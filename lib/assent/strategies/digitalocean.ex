defmodule Assent.Strategy.Digitalocean do
  @moduledoc """
  DigitalOcean OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """

  use Assent.Strategy.OAuth2.Base
  alias Assent.Config

  @impl true
  def default_config(config) do
    [
      site: "https://cloud.digitalocean.com/v1/oauth",
      authorize_url: "/authorize",
      token_url: "/token",
      user_url: "https://api.digitalocean.com/v2/account",
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
