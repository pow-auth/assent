defmodule Assent.Strategy.AzureAD do
  @moduledoc """
  Azure Active Directory OpenID Connect strategy.

  ## Configuration

  - `:client_id` - The OAuth2 client id, required
  - `:tenant_id` - The Azure tenant ID, optional, defaults to `common`
  - `:nonce` - The session based nonce, required
  - `:resource` - The Azure resource, optional, defaults to
    `https://graph.microsoft.com/`

  See `Assent.Strategy.OIDC` for more.

  ## Nonce

  You must provide a `:nonce` in your config when calling `authorize_url/1`.
  `:nonce` will be returned in the `:session_params` along with `:state`. You
  can use this to store the value in the current session e.g. a HTTPOnly
  session cookie.

  A random value generator could look like this:

      16
      |> :crypto.strong_rand_bytes()
      |> Base.encode64(padding: false)

  The `:session_params` should be fetched before the callback. See
  `Assent.Strategy.OIDC.authorize_url/1` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        nonce: "DYNAMICALLY_REPLACE_WITH_SESSION_NONCE"
      ]

  A tenant id can be set to limit scope of users who can get access (defaults
  to "common"):

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        nonce: "DYNAMICALLY_REPLACE_WITH_SESSION_NONCE",
        tenant_id: "REPLACE_WITH_TENANT_ID"
      ]

  The resource that client should pull a token for defaults to
  `https://graph.microsoft.com/`. It can be overridden with the
  `resource` key (or the `authorization_params` key):

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        nonce: "DYNAMICALLY_REPLACE_WITH_SESSION_NONCE",
        tenant_id: "REPLACE_WITH_TENANT_ID",
        resource: "https://service.contoso.com/"
      ]

  ## Setting up Azure AD

  Login to Azure, and set up a new application:
  https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-openid-connect-code#register-your-application-with-your-ad-tenant

  * `client_id` is the "Application ID".
  * The callback URL should be added to Redirect URI for the application.
  * "Sign in and read user profile" permission has to be enabled.

  ### App ID URI for `resource`

  To find the App ID URI to be used for `resource`, in the Azure Portal, click
  Azure Active Directory, click Application registrations, open the
  application's Settings page, then click Properties.
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.Config

  @impl true
  def default_config(config) do
    tenant_id = Config.get(config, :tenant_id, "common")
    resource  = Config.get(config, :resource, "https://graph.microsoft.com/")

    [
      site: "https://login.microsoftonline.com/#{tenant_id}/v2.0",
      authorization_params: [response_type: "id_token code", resource: resource],
      client_auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user), do: {:ok, user}

  @impl true
  def get_user(config, token) do
    case Helpers.verify_jwt(token["id_token"], nil, config) do
      {:ok, jwt}      -> {:ok, jwt.claims}
      {:error, error} -> {:error, error}
    end
  end
end
