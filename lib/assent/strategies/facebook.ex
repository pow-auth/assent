defmodule Assent.Strategy.Facebook do
  @moduledoc """
  Facebook OAuth 2.0 strategy.

  ## Configuration

  - `:user_url_request_fields` - The fields for the resource, defaults to
    `email,name,first_name,last_name,middle_name,link`

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, Strategy.OAuth2}

  @api_version "4.0"

  @impl true
  def default_config(_config) do
    [
      site: "https://graph.facebook.com/v#{@api_version}",
      authorize_url: "https://www.facebook.com/v#{@api_version}/dialog/oauth",
      token_url: "/oauth/access_token",
      user_url: "/me",
      authorization_params: [scope: "email"],
      user_url_request_fields: "email,name,first_name,last_name,middle_name,link",
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(config, user) do
    with {:ok, site} <- Config.fetch(config, :site) do
      {:ok, %{
        "sub"                => user["id"],
        "name"               => user["name"],
        "given_name"         => user["first_name"],
        "middle_name"        => user["middle_name"],
        "family_name"        => user["last_name"],
        "profile"            => user["link"],
        "picture"            => picture_url(site, user),
        "email"              => user["email"]
      }}
    end
  end

  defp picture_url(site, user) do
    "#{site}/#{user["id"]}/picture"
  end

  @impl true
  def get_user(config, access_token) do
    with {:ok, fields} <- Config.fetch(config, :user_url_request_fields),
         {:ok, client_secret} <- Config.fetch(config, :client_secret) do
      params = [
        appsecret_proof: appsecret_proof(access_token, client_secret),
        fields: fields,
        access_token: access_token["access_token"]
      ]

      OAuth2.get_user(config, access_token, params)
    end
  end

  defp appsecret_proof(access_token, client_secret) do
    :sha256
    |> :crypto.hmac(client_secret, access_token["access_token"])
    |> Base.encode16(case: :lower)
  end
end
