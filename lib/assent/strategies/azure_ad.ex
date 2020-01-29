defmodule Assent.Strategy.AzureAD do
  @moduledoc """
  Azure Active Directory OpenID Connect strategy.

  ## Configuration

  - `:client_id` - The OAuth2 client id, required
  - `:tenant_id` - The Azure tenant ID, optional, defaults to `common`
  - `:nonce` - The session based nonce, required
  - `:response_type` - The response type to request, defaults to `id_token code`

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

  The response type can be overridden in the configuration. If the value is set to `code` 
  the `id_token` value is still returned but the configuration for implicit flow is not required 
  in the Azure portal. 

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        nonce: "DYNAMICALLY_REPLACE_WITH_SESSION_NONCE",
        tenant_id: "REPLACE_WITH_TENANT_ID",
        response_type: "code"
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
    response_type = Config.get(config, :response_type, "id_token code")

    [
      site: "https://login.microsoftonline.com/#{tenant_id}/v2.0",
      authorization_params: [response_type: response_type, scope: "email profile", response_mode: "form_post"],
      client_auth_method: :client_secret_post,
    ]
  end

  @impl true
  def normalize(_config, user), do: {:ok, user}

  @impl true
  def get_user(_config, %{"id_token" => %{claims: claims}}),
    do: {:ok, claims}
end
