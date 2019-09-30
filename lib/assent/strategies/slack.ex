defmodule Assent.Strategy.Slack do
  @moduledoc """
  Slack OAuth 2.0 strategy.

  ## Configuration

  - `:team_id` - The team id to restrict authorization for, optional, defaults to nil

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]

  By default, the user can decide what team should be used for authorization.
  If you want to limit to a specific team, please pass a team id to the
  configuration:

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        team_id: "XXXXXXX"
      ]

  This value will be not be used if you set a `authorization_params` key.
  Instead you should set `team: TEAM_ID` in the `authorization_params` keyword
  list.
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.Config

  @spec default_config(Config.t()) :: Config.t()
  def default_config(config) do
    [
      site: "https://slack.com",
      token_url: "/api/oauth.access",
      user_url: "/api/users.identity",
      team_url: "/api/team.info",
      authorization_params: authorization_params(config),
      auth_method: :client_secret_post
    ]
  end

  defp authorization_params(config) do
    default = [scope: "identity.basic identity.email identity.avatar"]
    case Config.fetch(config, :team_id) do
      {:ok, team_id} -> Config.put(default, :team, team_id)
      _error         -> default
    end
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, identity) do
    {:ok, %{
      "uid"       => uid(identity),
      "name"      => identity["user"]["name"],
      "email"     => identity["user"]["email"],
      "image"     => identity["user"]["image_48"],
      "team_name" => identity["team"]["name"]}}
  end

  defp uid(%{"user" => %{"id" => id}, "team" => %{"id" => team_id}}), do: "#{id}-#{team_id}"
end
