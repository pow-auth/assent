defmodule Assent.Strategy.Gitlab do
  @moduledoc """
  Gitlab OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.Config

  @spec default_config(Config.t()) :: Config.t()
  def default_config(_config) do
    [
      site: "https://gitlab.com",
      authorize_url: "/oauth/authorize",
      token_url: "/oauth/token",
      user_url: "/api/v4/user",
      authorization_params: [scope: "api read_user read_registry"],
      auth_method: :client_secret_post
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"        => user["id"],
      "name"       => user["name"],
      "nickname"   => user["username"],
      "email"      => user["email"],
      "location"   => user["location"],
      "image"      => user["avatar_url"],
      "urls"       => %{
        "web_url"     => user["web_url"],
        "website_url" => user["website_url"]
      }
    }}
  end
end
