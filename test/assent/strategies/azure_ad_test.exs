defmodule Assent.Strategy.AzureADTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.AzureAD

  # From https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
  @id_token_claims %{
    "ver" => "2.0",
    "iss" => "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
    "sub" => "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
    "aud" => "6cb04018-a3f5-46a7-b995-940c78f5aef3",
    "exp" => :os.system_time(:second) + 60,
    "iat" => :os.system_time(:second),
    "nbf" => :os.system_time(:second),
    "name" => "Abe Lincoln",
    "preferred_username" => "AbeLi@microsoft.com",
    "oid" => "00000000-0000-0000-66f3-3332eca7ea81",
    "tid" => "3338040d-6c67-4c5b-b112-36a304b66dad",
    "nonce" => "123523",
    "aio" =>
      "Df2UVXL1ix!lMCWMSOJBcFatzcGfvFGhjKv8q5g0x732dR5MB5BisvGQO7YWByjd8iQDLq!eGbIDakyp5mnOrcdqHeYSnltepQmRp6AIZ8jY"
  }

  @user %{
    "name" => "Abe Lincoln",
    "preferred_username" => "AbeLi@microsoft.com",
    "sub" => "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
    "aio" =>
      "Df2UVXL1ix!lMCWMSOJBcFatzcGfvFGhjKv8q5g0x732dR5MB5BisvGQO7YWByjd8iQDLq!eGbIDakyp5mnOrcdqHeYSnltepQmRp6AIZ8jY",
    "oid" => "00000000-0000-0000-66f3-3332eca7ea81",
    "tid" => "3338040d-6c67-4c5b-b112-36a304b66dad",
    "ver" => "2.0"
  }

  test "authorize_url/1 with default `tenant_id: common`", %{config: config} do
    config = Keyword.drop(config, [:base_url, :openid_configuration])

    assert {:ok, %{url: url}} = AzureAD.authorize_url(config)
    assert url =~ "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    assert url =~ "scope=openid+email+profile"
    assert url =~ "response_mode=form_post"
  end

  test "authorize_url/1 with `tenant_id: domain` with `:base_url` option", %{config: config} do
    base_url = "https://login.microsoftonline.us/contoso.onmicrosoft.com/v2.0"

    config =
      config
      |> Keyword.delete(:openid_configuration)
      |> Keyword.merge(
        base_url: base_url,
        tenant_id: "contoso.onmicrosoft.com"
      )

    assert {:ok, %{url: url}} = AzureAD.authorize_url(config)

    assert url =~
             "https://login.microsoftonline.us/contoso.onmicrosoft.com/oauth2/v2.0/authorize"
  end

  test "authorize_url/1 with `tenant_id: tenant_id`", %{config: config} do
    tenant_id = "3338040d-6c67-4c5b-b112-36a304b66dad"
    base_url = TestServer.url("/#{tenant_id}/v2.0")

    openid_config = %{
      "issuer" => base_url,
      "authorization_endpoint" => TestServer.url("/#{tenant_id}/oauth2/v2.0/authorize")
    }

    expect_openid_config_request(openid_config,
      uri: "/#{tenant_id}/v2.0/.well-known/openid-configuration"
    )

    config =
      config
      |> Keyword.delete(:openid_configuration)
      |> Keyword.merge(base_url: base_url, tenant_id: tenant_id)

    assert {:ok, %{url: url}} = AzureAD.authorize_url(config)
    assert url =~ "/#{tenant_id}/oauth2/v2.0/authorize"
  end

  test "callback/2 with `tenant_id: tenant_id`", %{config: config, callback_params: params} do
    tenant_id = "9188040d-6c67-4c5b-b112-36a304b66dad"

    config =
      tenant_config(config, tenant_id, %{
        "issuer" => "https://login.microsoftonline.com/#{tenant_id}/v2.0",
        "jwks_uri" => TestServer.url("/jwks_uri.json")
      })

    [key | _rest] = expect_oidc_jwks_uri_request()

    expect_oidc_access_token_request(
      uri: "/#{tenant_id}/oauth2/v2.0/token",
      id_token_opts: [claims: @id_token_claims, kid: key["kid"]]
    )

    assert {:ok, %{user: user}} = AzureAD.callback(config, params)
    assert user == @user
  end

  test "callback/2 with default `tenant_id: common`", %{config: config, callback_params: params} do
    tenant_id = @id_token_claims["tid"]
    issuer = TestServer.url("/#{tenant_id}/v2.0")

    expect_openid_config_request(
      %{"issuer" => issuer, "jwks_uri" => TestServer.url("/jwks_uri.json")},
      uri: "/#{tenant_id}/v2.0/.well-known/openid-configuration"
    )

    [key | _rest] = expect_oidc_jwks_uri_request()
    claims = Map.put(@id_token_claims, "iss", issuer)

    config =
      config
      |> Keyword.delete(:openid_configuration)
      |> Keyword.merge(
        base_url: TestServer.url("/common/v2.0"),
        client_id: "6cb04018-a3f5-46a7-b995-940c78f5aef3",
        session_params: Map.put(config[:session_params], :nonce, "123523")
      )

    expect_oidc_access_token_request(
      uri: "/common/oauth2/v2.0/token",
      id_token_opts: [claims: claims, kid: key["kid"]]
    )

    assert {:ok, %{user: user}} = AzureAD.callback(config, params)
    assert user == @user
  end

  test "callback/2 with `tenant_id: domain` with claim missing `tid`", %{
    config: config,
    callback_params: params
  } do
    config = tenant_config(config, "contoso.onmicrosoft.com")
    claims = Map.delete(@id_token_claims, "tid")

    expect_oidc_access_token_request(
      uri: "/contoso.onmicrosoft.com/oauth2/v2.0/token",
      id_token_opts: [claims: claims]
    )

    assert AzureAD.callback(config, params) == {:error, "Missing `tid` in ID Token claims"}
  end

  test "callback/2 with `tenant_id: domain` with claim with invalid `tid`", %{
    config: config,
    callback_params: params
  } do
    config = tenant_config(config, "contoso.onmicrosoft.com")
    claims = Map.put(@id_token_claims, "tid", "invalid")

    expect_oidc_access_token_request(
      uri: "/contoso.onmicrosoft.com/oauth2/v2.0/token",
      id_token_opts: [claims: claims]
    )

    assert AzureAD.callback(config, params) == {:error, "Invalid `tid` in ID Token claims"}
  end

  test "callback/2 with `tenant_id: domain` with claim with UUID `tid` with invalid characters",
       %{
         config: config,
         callback_params: params
       } do
    config = tenant_config(config, "contoso.onmicrosoft.com")
    claims = Map.put(@id_token_claims, "tid", "00000000-0000-0000-0000-00000000000g")

    expect_oidc_access_token_request(
      uri: "/contoso.onmicrosoft.com/oauth2/v2.0/token",
      id_token_opts: [claims: claims]
    )

    assert AzureAD.callback(config, params) == {:error, "Invalid `tid` in ID Token claims"}
  end

  defp tenant_config(config, tenant, openid_configuration \\ %{}) do
    session_params = Map.put(config[:session_params], :nonce, "123523")

    openid_configuration =
      Map.put_new(
        openid_configuration,
        "token_endpoint",
        TestServer.url("/#{tenant}/oauth2/v2.0/token")
      )

    Keyword.merge(
      config,
      openid_configuration: openid_configuration,
      tenant_id: tenant,
      base_url: TestServer.url("/#{tenant}/v2.0"),
      client_id: "6cb04018-a3f5-46a7-b995-940c78f5aef3",
      session_params: session_params
    )
  end
end
