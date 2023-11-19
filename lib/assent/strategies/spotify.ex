defmodule Assent.Strategy.Spotify do
  @moduledoc """
  Spotify OAuth 2.0 strategy.

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
      base_url: "https://api.spotify.com/v1",
      authorize_url: "https://accounts.spotify.com/authorize",
      token_url: "https://accounts.spotify.com/api/token",
      user_url: "/me",
      authorization_params: [scope: "user-read-email"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "name" => user["display_name"],
       "preferred_username" => user["display_name"],
       "email" => user["email"],
       "picture" => picture_url(user)
     }}
  end

  defp picture_url(user) do
    List.first(user["images"])["url"]
  end
end
