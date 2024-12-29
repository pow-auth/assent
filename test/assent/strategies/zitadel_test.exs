defmodule Assent.Strategy.ZitadelTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Zitadel

  @client_id "3425235252@nameofproject"
  @resource_id "3425296767"
  @id_token_claims %{
    "iss" => "https://subdomain.region.zitadel.cloud",
    "sub" => "299884084107794421",
    "aud" => [@client_id, @resource_id],
    "exp" => :os.system_time(:second) + 5 * 60,
    "iat" => :os.system_time(:second),
    "auth_time" => :os.system_time(:second) - 60,
    "amr" => ["pwd"],
    "azp" => @client_id,
    "client_id" => @client_id,
    "at_hash" => "at_hash",
    "sid" => "sid"
  }
  @userinfo %{
    "email" => "john.doe@example.com",
    "email_verified" => true,
    "family_name" => "Admin",
    "given_name" => "ZITADEL",
    "locale" => "en",
    "name" => "ZITADEL Admin",
    "preferred_username" => "john.doe@example.com",
    "sub" => "299884084107794421",
    "updated_at" => 1_735_240_843
  }
  @user %{
    "sub" => "299884084107794421",
    "email" => "john.doe@example.com",
    "email_verified" => true,
    "family_name" => "Admin",
    "given_name" => "ZITADEL",
    "locale" => "en",
    "name" => "ZITADEL Admin",
    "preferred_username" => "john.doe@example.com",
    "updated_at" => 1_735_240_843
  }

  setup %{config: config} do
    openid_configuration =
      Map.put(config[:openid_configuration], "issuer", "https://subdomain.region.zitadel.cloud")

    session_params = Map.put(config[:session_params], :code_verifier, "code_verifier_value")

    config =
      Keyword.merge(
        config,
        client_id: @client_id,
        openid_configuration: openid_configuration,
        session_params: session_params,
        resource_id: @resource_id
      )

    {:ok, config: config}
  end

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url, session_params: session_params}} = Zitadel.authorize_url(config)

    assert session_params[:code_verifier]

    url = URI.parse(url)

    assert url.path == "/oauth/authorize"

    assert %{"client_id" => @client_id, "scope" => scope, "code_challenge_method" => "S256"} =
             URI.decode_query(url.query)

    assert scope =~ "email profile"
  end

  test "callback/2", %{config: config, callback_params: params} do
    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: @id_token_claims, kid: key["kid"]])
    expect_oidc_userinfo_request(@userinfo)

    assert {:ok, %{user: user}} = Zitadel.callback(config, params)
    assert user == @user
  end
end
