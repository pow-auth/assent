defmodule Assent.Strategy.Google do
  @moduledoc """
  Google OAuth 2.0 strategy.

  In the normalized user response a `google_hd` ("Hosted Domain") field is
  included in user parameters and can be used to limit access to users
  belonging to a particular hosted domain.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  To get the refresh token, it's necessary to pass `access_type: "offline"` in
  the authorization request:

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        authorization_params: [
          access_type: "offline",
          scope: "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
        ]
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OAuth2.Base

  @impl true
  def default_config(_config) do
    [
      base_url: "https://www.googleapis.com",
      authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
      token_url: "/oauth2/v4/token",
      user_url: "/oauth2/v3/userinfo",
      authorization_params: [
        scope:
          "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
      ],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["sub"],
       "name" => user["name"],
       "given_name" => user["given_name"],
       "family_name" => user["family_name"],
       "picture" => user["picture"],
       "email" => user["email"],
       "email_verified" => user["email_verified"],
       "locale" => user["locale"]
     },
     %{
       "google_hd" => user["hd"]
     }}
  end
end
