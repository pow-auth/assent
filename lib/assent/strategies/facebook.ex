defmodule Assent.Strategy.Facebook do
  @moduledoc """
  Facebook OAuth 2.0 strategy.

  ## Configuration

  - `:user_url_request_fields` - The fields for the resource, defaults to "name,email"

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, Strategy.OAuth2}

  @api_version "2.12"

  @spec default_config(Config.t()) :: Config.t()
  def default_config(_config) do
    [
      site: "https://graph.facebook.com/v#{@api_version}",
      authorize_url: "https://www.facebook.com/v#{@api_version}/dialog/oauth",
      token_url: "/oauth/access_token",
      user_url: "/me",
      authorization_params: [scope: "email"],
      user_url_request_fields: "name,email"
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(config, user) do
    with {:ok, site} <- Config.fetch(config, :site) do
      {:ok, %{
        "uid"         => user["id"],
        "nickname"    => user["username"],
        "email"       => user["email"],
        "name"        => user["name"],
        "first_name"  => user["first_name"],
        "last_name"   => user["last_name"],
        "location"    => (user["location"] || %{})["name"],
        "image"       => "#{site}/#{user["id"]}/picture",
        "description" => user["bio"],
        "urls"        => %{
          "Facebook"  => user["link"],
          "Website"   => user["website"]},
        "verified"    => user["verified"]
      }}
        end
  end

  @spec get_user(Config.t(), map()) :: {:ok, map()} | {:error, term()}
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
