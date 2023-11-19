defmodule Assent.Strategy.Instagram do
  @moduledoc """
  Instagram OAuth 2.0 strategy.

  The Instagram user object does not provide data on email verification, email
  is considered unverified.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, Strategy.OAuth2}

  @impl true
  def default_config(_config) do
    [
      base_url: "https://graph.instagram.com",
      authorize_url: "https://api.instagram.com/oauth/authorize",
      token_url: "https://api.instagram.com/oauth/access_token",
      user_url: "/me",
      user_url_request_fields: "id,username",
      authorization_params: [scope: "user_profile"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def fetch_user(config, access_token) do
    with {:ok, fields} <- Config.fetch(config, :user_url_request_fields) do
      params = [
        fields: fields,
        access_token: access_token["access_token"]
      ]

      OAuth2.fetch_user(config, access_token, params)
    end
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "preferred_username" => user["username"]
     }}
  end
end
