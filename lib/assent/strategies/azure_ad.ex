defmodule Assent.Strategy.AzureAD do
  @moduledoc """
  Azure Active Directory OpenID Connect strategy.

  ## Configuration

    * `:tenant_id` - the tenant identifier, optional, defaults to `common`.
      May be a directory ID, verified domain, or one of `common`,
      `organizations`, or `consumers`.

    * `:base_url` - the Microsoft identity platform issuer, optional, defaults
      to `https://login.microsoftonline.com/{tenant_id}/v2.0`

  See `Assent.Strategy.OIDC` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  A tenant identifier can be set to limit which users can get access:

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        tenant_id: "REPLACE_WITH_TENANT_ID",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  ## Setting up Azure AD

  Login to Azure, and [set up a new
  application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app):

  * The callback URL should be added to "Redirect URI" for the application.
  * `client_id` is the "Application ID".
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.Strategy.OIDC

  @impl true
  def default_config(config) do
    tenant_id = Keyword.get(config, :tenant_id, "common")

    base_url =
      Keyword.get(config, :base_url, "https://login.microsoftonline.com/#{tenant_id}/v2.0")

    default_config = [
      base_url: base_url,
      authorization_params: [scope: "email profile", response_mode: "form_post"],
      client_authentication_method: "client_secret_post",
      tenant_id: tenant_id
    ]

    case uuid?(tenant_id) do
      true ->
        default_config

      false ->
        endpoint_base_url = String.replace_suffix(base_url, "/v2.0", "")

        openid_configuration = %{
          "authorization_endpoint" => "#{endpoint_base_url}/oauth2/v2.0/authorize",
          "token_endpoint" => "#{endpoint_base_url}/oauth2/v2.0/token"
        }

        Keyword.put(default_config, :openid_configuration, openid_configuration)
    end
  end

  defp uuid?(
         <<a::binary-size(8), "-", b::binary-size(4), "-", c::binary-size(4), "-",
           d::binary-size(4), "-", e::binary-size(12)>>
       ) do
    match?({:ok, _decoded}, Base.decode16(a <> b <> c <> d <> e, case: :mixed))
  end

  defp uuid?(_tenant_id), do: false

  @impl true
  def fetch_user(config, token) do
    with {:ok, config} <- prepare_config(config, token) do
      OIDC.fetch_user(config, token)
    end
  end

  defp prepare_config(config, %{"id_token" => id_token}) do
    case uuid?(Keyword.fetch!(config, :tenant_id)) do
      true -> {:ok, config}
      false -> prepare_tenant_specific_config(config, id_token)
    end
  end

  defp prepare_config(config, _token), do: {:ok, config}

  defp prepare_tenant_specific_config(config, id_token) do
    with {:ok, jwt} <- Helpers.verify_jwt(id_token, nil, config),
         {:ok, tenant_id} <- fetch_tenant_id(jwt.claims) do
      {:ok, base_url} = Assent.fetch_config(config, :base_url)
      uri = %{URI.parse(base_url) | path: "/#{tenant_id}/v2.0"}

      config =
        config
        # Discards the authority OpenID configuration so `OIDC.fetch_user/2`
        # can fetch the tenant-specific OpenID configuration for token
        # validation.
        |> Keyword.delete(:openid_configuration)
        |> Keyword.put(:base_url, URI.to_string(uri))

      {:ok, config}
    end
  end

  defp fetch_tenant_id(%{"tid" => tenant_id}) do
    case uuid?(tenant_id) do
      true -> {:ok, tenant_id}
      false -> {:error, "Invalid `tid` in ID Token claims"}
    end
  end

  defp fetch_tenant_id(_claims), do: {:error, "Missing `tid` in ID Token claims"}
end
