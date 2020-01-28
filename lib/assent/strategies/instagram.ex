defmodule Assent.Strategy.Instagram do
  @moduledoc """
  Instagram OAuth 2.0 strategy.

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
      site: "https://api.instagram.com",
      authorization_params: [scope: "basic"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok, %{
      "sub"                => user["id"],
      "name"               => user["full_name"],
      "preferred_username" => user["username"],
      "picture"            => user["profile_picture"]
    }}
  end

  @impl true
  def get_user(_config, token) do
    {:ok, token["user"]}
  end
end
