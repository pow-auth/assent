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
    "aio" => "Df2UVXL1ix!lMCWMSOJBcFatzcGfvFGhjKv8q5g0x732dR5MB5BisvGQO7YWByjd8iQDLq!eGbIDakyp5mnOrcdqHeYSnltepQmRp6AIZ8jY"
  }
  @user %{
    "name" => "Abe Lincoln",
    "preferred_username" => "AbeLi@microsoft.com",
    "sub" => "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = AzureAD.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id=id"
    assert url =~ "scope=openid+email+profile"
    assert url =~ "response_mode=form_post"
  end

  test "callback/2", %{config: config, callback_params: params} do
    openid_config =
      config[:openid_configuration]
      |> Map.put("issuer", "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0")
      |> Map.put("token_endpoint_auth_methods_supported", ["client_secret_post", "private_key_jwt", "client_secret_basic"])

    session_params = Map.put(config[:session_params], :nonce, "123523")
    config         = Keyword.merge(config, openid_configuration: openid_config, tenant_id: "9188040d-6c67-4c5b-b112-36a304b66dad", client_id: "6cb04018-a3f5-46a7-b995-940c78f5aef3", session_params: session_params)

    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: @id_token_claims, kid: key["kid"]])

    assert {:ok, %{user: user}} = AzureAD.callback(config, params)
    assert user == @user
  end
end
