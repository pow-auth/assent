defmodule Assent.Strategy.Twitter do
  @moduledoc """
  Twitter OAuth strategy.

  ## Usage

      config = [
        consumer_key: "REPLACE_WITH_CONSUMER_KEY",
        consumer_secret: "REPLACE_WITH_CONSUMER_SECRET"
      ]
  """
  use Assent.Strategy.OAuth.Base

  @impl true
  def default_config(_config) do
    [
      site: "https://api.twitter.com",
      user_url: "/1.1/account/verify_credentials.json?include_entities=false&skip_status=true&include_email=true",
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok, %{
      "sub"                => user["id"],
      "name"               => user["name"],
      "preferred_username" => user["screen_name"],
      "profile"            => "https://twitter.com/#{user["screen_name"]}",
      "picture"            => user["profile_image_url_https"],
      "website"            => user["url"],
      "email"              => user["email"]
    }}
  end
end
