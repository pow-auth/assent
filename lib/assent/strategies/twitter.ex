defmodule Assent.Strategy.Twitter do
  @moduledoc """
  Twitter OAuth strategy.

  The Twitter user endpoint only returns verified email, `email_verified` will
  always be `true`.

  ## Usage

      config = [
        consumer_key: "REPLACE_WITH_CONSUMER_KEY",
        consumer_secret: "REPLACE_WITH_CONSUMER_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth` for more.
  """
  use Assent.Strategy.OAuth.Base

  alias Assent.{CallbackError, Strategy.OAuth.Base}

  @impl true
  def default_config(_config) do
    [
      base_url: "https://api.twitter.com",
      request_token_url: "/oauth/request_token",
      authorize_url: "/oauth/authenticate",
      access_token_url: "/oauth/access_token",
      user_url:
        "/1.1/account/verify_credentials.json?include_entities=false&skip_status=true&include_email=true"
    ]
  end

  @doc false
  @impl true
  def callback(config, params) do
    case Map.has_key?(params, "denied") do
      true ->
        {:error, CallbackError.exception(message: "The user denied the authorization request")}

      false ->
        Base.callback(config, params, __MODULE__)
    end
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "name" => user["name"],
       "preferred_username" => user["screen_name"],
       "profile" => "https://twitter.com/#{user["screen_name"]}",
       "picture" => user["profile_image_url_https"],
       "website" => user["url"],
       "email" => user["email"],
       "email_verified" => true
     }}
  end
end
