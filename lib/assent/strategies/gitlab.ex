defmodule Assent.Strategy.Gitlab do
  @moduledoc """
  Gitlab OAuth 2.0 strategy.

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
      base_url: "https://gitlab.com",
      authorize_url: "/oauth/authorize",
      token_url: "/oauth/token",
      user_url: "/api/v4/user",
      authorization_params: [scope: "api read_user read_registry"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "name" => user["name"],
       "preferred_username" => user["username"],
       "picture" => user["avatar_url"],
       "email" => user["email"],
       "email_verified" => not is_nil(user["confirmed_at"])
     }}
  end
end
