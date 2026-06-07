defmodule Assent.Strategy.Zitadel do
  @moduledoc """
  Zitadel OpenID Connect strategy.

  ## Configuration

    * `:resource_id` - the resource ID, required

  See `Assent.Strategy.OIDC` for more.

  ## Usage

      config = [
        base_url: "REPLACE_WITH_ORGANIZATION_URL",
        client_id: "REPLACE_WITH_CLIENT_ID",
        resource_id: "REPLACE_WITH_RESOURCE_ID"
      ]
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.Strategy.OIDC

  @impl true
  def default_config(config) do
    trusted_audiences =
      config
      |> Keyword.get(:resource_id)
      |> List.wrap()

    [
      authorization_params: [scope: "email profile"],
      client_authentication_method: "none",
      code_verifier: true,
      trusted_audiences: trusted_audiences
    ]
  end

  def fetch_user(config, token), do: OIDC.fetch_userinfo(config, token)
end
