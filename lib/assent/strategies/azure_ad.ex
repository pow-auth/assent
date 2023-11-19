defmodule Assent.Strategy.AzureAD do
  @moduledoc """
  Azure Active Directory OpenID Connect strategy.

  ## Configuration

  - `:tenant_id` - The Azure tenant ID, optional, defaults to `common`

  See `Assent.Strategy.OIDC` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  A tenant id can be set to limit scope of users who can get access (defaults
  to "common"):

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        tenant_id: "REPLACE_WITH_TENANT_ID",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  ## Setting up Azure AD

  Login to Azure, and set up a new application:
  https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app

  * The callback URL should be added to "Redirect URI" for the application.
  * `client_id` is the "Application ID".
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.Config

  @impl true
  def default_config(config) do
    tenant_id = Config.get(config, :tenant_id, "common")

    [
      base_url: "https://login.microsoftonline.com/#{tenant_id}/v2.0",
      authorization_params: [scope: "email profile", response_mode: "form_post"],
      client_authentication_method: "client_secret_post"
    ]
  end
end
