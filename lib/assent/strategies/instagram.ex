defmodule Assent.Strategy.Instagram do
  @moduledoc """
  Instagram OAuth 2.0 strategy.

  The Instagram user object does not provide data on email verification, email
  is considered unverified.

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
      site: "https://graph.instagram.com",
      authorize_url: "https://api.instagram.com/oauth/authorize",
      token_url: "https://api.instagram.com/oauth/access_token",
      user_url: "/me",
      authorization_params: [scope: "user_profile"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok, %{
      "sub"                => user["id"],
      "preferred_username" => user["username"]
    }}
  end
end
