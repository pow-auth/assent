defmodule Assent.Strategy.Bitbucket do
  @moduledoc """
  Bitbucket OAuth 2.0 strategy.

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
      base_url: "https://api.bitbucket.org",
      authorize_url: "https://bitbucket.org/site/oauth2/authorize",
      token_url: "https://bitbucket.org/site/oauth2/access_token",
      user_url: "/2.0/user",
      authorization_params: [
        scope: "project issue team pullrequest runner account email pipeline",
      ],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["account_id"],
       "nickname" => user["nickname"],
       "preferred_username" => user["username"],
       "name" => user["display_name"]
     }}
  end
end
