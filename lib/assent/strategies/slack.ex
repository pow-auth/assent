defmodule Assent.Strategy.Slack do
  @moduledoc """
  Slack OAuth 2.0 OpenID Connect strategy.

  The Slack user endpoint does not provide data on email verification, email is
  considered unverified.

  ## Configuration

  - `:team_id` - The team id to restrict authorization for, optional, defaults to nil

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  By default, the user can decide what team should be used for authorization.
  If you want to limit to a specific team, please pass a team id to the
  configuration:

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        team_id: "REPLACE_WITH_TEAM_ID",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  This value will be not be used if you set a `authorization_params` key.
  Instead you should set `team: TEAM_ID` in the `authorization_params` keyword
  list.
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.Config

  @impl true
  def default_config(config) do
    [
      base_url: "https://slack.com",
      authorization_params: authorization_params(config),
      client_authentication_method: "client_secret_post"
    ]
  end

  defp authorization_params(config) do
    default = [scope: "openid email profile"]

    case Config.fetch(config, :team_id) do
      {:ok, team_id} -> Config.put(default, :team, team_id)
      _error -> default
    end
  end
end
