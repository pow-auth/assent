defmodule Assent.Strategy.Discord do
  @moduledoc """
  Discord OAuth 2.0 strategy.

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
      site: "https://discordapp.com/api",
      authorize_url: "/oauth2/authorize",
      token_url: "/oauth2/token",
      user_url: "/users/@me",
      authorization_params: [scope: "identify email"]
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"   => user["id"],
      "name"  => user["username"],
      "email" => verified_email(user),
      "image" => "https://cdn.discordapp.com/avatars/#{user["id"]}/#{user["avatar"]}"}}
  end

  defp verified_email(%{"verified" => true} = user), do: user["email"]
  defp verified_email(_), do: nil
end
