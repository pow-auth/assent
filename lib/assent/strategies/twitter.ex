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

  alias Assent.Config

  @spec default_config(Config.t()) :: Config.t()
  def default_config(_config) do
    [
      site: "https://api.twitter.com",
      user_url: "/1.1/account/verify_credentials.json?include_entities=false&skip_status=true&include_email=true",
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"         => user["id"],
      "nickname"    => user["screen_name"],
      "email"       => user["email"],
      "location"    => user["location"],
      "name"        => user["name"],
      "image"       => user["profile_image_url_https"],
      "description" => user["description"],
      "urls"        => %{"Website" => user["url"],
                        "Twitter" => "https://twitter.com/#{user["screen_name"]}"}}}
  end
end
