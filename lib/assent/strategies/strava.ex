defmodule Assent.Strategy.Strava do
  @moduledoc """
  Strava OAuth strategy.

  The athlete endpoint, describing the currently authenticated user, does not
  return an email address - [changelog](https://developers.strava.com/docs/changelog/#january-17-2019).

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
      base_url: "https://www.strava.com/api/v3",
      authorize_url: "https://www.strava.com/oauth/authorize",
      token_url: "/oauth/token",
      user_url: "/athlete",
      authorization_params: [scope: "read_all,profile:read_all"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "given_name" => user["firstname"],
       "family_name" => user["lastname"],
       "preferred_username" => user["username"],
       "picture" => user["profile"]
     }}
  end
end
