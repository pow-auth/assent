defmodule Assent.Strategy.Discord do
  @moduledoc """
  Discord OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OAuth2.Base

  @impl true
  def default_config(_config) do
    [
      base_url: "https://discordapp.com/api",
      authorize_url: "/oauth2/authorize",
      token_url: "/oauth2/token",
      user_url: "/users/@me",
      authorization_params: [scope: "identify email"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "preferred_username" => user["username"],
       "email" => user["email"],
       "email_verified" => user["verified"],
       "picture" => picture_url(user)
     }}
  end

  defp picture_url(user) do
    "https://cdn.discordapp.com/avatars/#{user["id"]}/#{user["avatar"]}"
  end
end
