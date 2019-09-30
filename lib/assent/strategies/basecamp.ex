defmodule Assent.Strategy.Basecamp do
  @moduledoc """
  Basecamp OAuth 2.0 strategy.

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
      site: "https://launchpad.37signals.com",
      authorize_url: "/authorization/new",
      token_url: "/authorization/token",
      user_url: "/authorization.json",
      authorization_params: [type: "web_server"],
      auth_method: :client_secret_post
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"        => user["identity"]["id"],
      "name"       => "#{user["identity"]["first_name"]} #{user["identity"]["last_name"]}",
      "first_name" => user["identity"]["first_name"],
      "last_name"  => user["identity"]["last_name"],
      "email"      => user["identity"]["email_address"],
      "accounts"   => user["accounts"]
    }}
  end
end
