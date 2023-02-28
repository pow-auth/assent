defmodule Assent.Strategy.LinkedInTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Linkedin

  # From https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2
  @id_token_claims %{
    "iss" => "https://www.linkedin.com",
    "sub" => "782bbtaQ",
    "name" => "John Doe",
    "given_name" => "John",
    "family_name" => "Doe",
    "picture" => "https://media.licdn-ei.com/dms/image/C5F03AQHqK8v7tB1HCQ/profile-displayphoto-shrink_100_100/0/",
    "locale" => "en-US",
    "email" => "doe@email.com",
    "email_verified" => true
  }
  @user %{
    "name" => "John Doe",
    "email" => "doe@email.com",
    "email_verified" => true,
    "given_name" => "John",
    "family_name" => "Doe",
    "locale" => "en-US",
    "picture" => "https://media.licdn-ei.com/dms/image/C5F03AQHqK8v7tB1HCQ/profile-displayphoto-shrink_100_100/0/",
    "sub" => "782bbtaQ"
  }

  @openid_config %{
    "issuer" => "https://www.linkedin.com",
    "authorization_endpoint" => "https://www.linkedin.com/oauth/v2/authorization",
    "token_endpoint" => "https://www.linkedin.com/oauth/v2/accessToken",
    "userinfo_endpoint" => "https://api.linkedin.com/v2/userinfo",
    "jwks_uri" => "https://www.linkedin.com/oauth/openid/jwks",
    "response_types_supported" => ["code"],
    "subject_types_supported" => ["pairwise"],
    "id_token_signing_alg_values_supported" => ["RS256"],
    "scopes_supported" => ["openid", "profile", "email"],
    "claims_supported" => ["iss", "aud", "iat", "exp", "sub", "name", "given_name", "family_name", "picture", "email", "email_verified", "locale"]
  }

  setup %{config: config} do
    openid_configuration = Map.merge(@openid_config, Map.delete(config[:openid_configuration], "issuer"))

    config = Keyword.put(config, :openid_configuration, openid_configuration)

    {:ok, config: config}
  end

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Linkedin.authorize_url(config)
    assert url =~ "scope=openid+profile+email"
  end

  test "callback/2", %{config: config, callback_params: params} do
    claims = Map.put(@id_token_claims, "aud", config[:client_id])

    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: claims, kid: key["kid"]])

    assert {:ok, %{user: user}} = Linkedin.callback(config, params)
    assert user == @user
  end
end
