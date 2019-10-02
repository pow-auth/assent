defmodule Assent.Strategy.AzureOAuth2 do
  @moduledoc """
  Azure AD OAuth 2.0 strategy.

  ## Configuration

  - `:tenant_id` - The Azure tenant ID, optional, defaults to `common`
  - `:resource` - The Azure resource, optional, defaults to `https://graph.microsoft.com/`

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]

  A tenant id can be set to limit scope of users who can get access (defaults
  to "common"):

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        tenant_id: "8eaef023-2b34-4da1-9baa-8bc8c9d6a490"
      ]

  The resource that client should pull a token for defaults to
  `https://graph.microsoft.com/`. It can be overridden with the
  `resource` key (or the `authorization_params` key):

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        tenant_id: "8eaef023-2b34-4da1-9baa-8bc8c9d6a490",
        resource: "https://service.contoso.com/"
      ]

  ## Setting up Azure AD

  Login to Azure, and set up a new application:
  https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code#register-your-application-with-your-ad-tenant

  * `client_id` is the "Application ID".
  * `client_secret` has to be created with a new key for the application.
  * The callback URL should be added to Reply URL's for the application.
  * "Sign in and read user profile" permission has to be enabled.

  ### App ID URI for `resource`

  To find the App ID URI to be used for `resource`, in the Azure Portal, click
  Azure Active Directory, click Application registrations, open the
  application's Settings page, then click Properties.
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.Config

  @spec default_config(Config.t()) :: Config.t()
  def default_config(config) do
    tenant_id = Config.get(config, :tenant_id, "common")
    resource  = Config.get(config, :resource, "https://graph.microsoft.com/")

    [
      site: "https://login.microsoftonline.com",
      authorize_url: "/#{tenant_id}/oauth2/authorize",
      token_url: "/#{tenant_id}/oauth2/token",
      authorization_params: [response_mode: "query", response_type: "code", resource: resource],
      auth_method: :client_secret_post
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"        => user["sub"],
      "name"       => "#{user["given_name"]} #{user["family_name"]}",
      "email"      => user["email"] || user["upn"],
      "first_name" => user["given_name"],
      "last_name"  => user["family_name"]}}
  end

  @spec get_user(Config.t(), map()) :: {:ok, map()} | {:error, term()}
  def get_user(config, token) do
    case Helpers.verify_jwt(token["id_token"], nil, config) do
      {:ok, jwt}      -> {:ok, jwt.claims}
      {:error, error} -> {:error, error}
    end
  end
end
