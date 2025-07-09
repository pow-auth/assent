defmodule Assent.Strategy.SlackTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Slack

  # From https://api.slack.com/authentication/sign-in-with-slack#implementation
  @id_token_claims %{
    "iss" => "https://slack.com",
    "sub" => "U0R7MFMJM",
    "aud" => "25259531569.1115258246291",
    "exp" => DateTime.to_unix(DateTime.utc_now()) + 60,
    "iat" => DateTime.to_unix(DateTime.utc_now()),
    "auth_time" => DateTime.to_unix(DateTime.utc_now()),
    "nonce" => "abcd",
    "at_hash" => "tUbyWGBHe0V32FJEupkgVQ",
    "https://slack.com/team_id" => "T0RR",
    "https://slack.com/user_id" => "U0JM",
    "email" => "bront@slack-corp.com",
    "email_verified" => true,
    "date_email_verified" => 1_622_128_723,
    "locale" => "en-US",
    "name" => "brent",
    "given_name" => "",
    "family_name" => "",
    "https://slack.com/team_image_230" => "https://secure.gravatar.com/avatar/bc.png",
    "https://slack.com/team_image_default" => true
  }

  @user %{
    "sub" => "U0R7MFMJM",
    "name" => "brent",
    "email" => "bront@slack-corp.com",
    "email_verified" => true,
    "family_name" => "",
    "given_name" => "",
    "locale" => "en-US",
    "https://slack.com/team_id" => "T0RR",
    "https://slack.com/user_id" => "U0JM",
    "date_email_verified" => 1_622_128_723,
    "https://slack.com/team_image_230" => "https://secure.gravatar.com/avatar/bc.png",
    "https://slack.com/team_image_default" => true
  }

  @openid_config %{
    "issuer" => "https://slack.com",
    "authorization_endpoint" => "https://slack.com/openid/connect/authorize",
    "token_endpoint" => "https://slack.com/api/openid.connect.token",
    "userinfo_endpoint" => "https://slack.com/api/openid.connect.userInfo",
    "jwks_uri" => "https://slack.com/openid/connect/keys",
    "scopes_supported" => ["openid", "profile", "email"],
    "response_types_supported" => ["code"],
    "response_modes_supported" => ["form_post"],
    "grant_types_supported" => ["authorization_code"],
    "subject_types_supported" => ["public"],
    "id_token_signing_alg_values_supported" => ["RS256"],
    "claims_supported" => ["sub", "auth_time", "iss"],
    "claims_parameter_supported" => false,
    "request_parameter_supported" => false,
    "request_uri_parameter_supported" => true,
    "token_endpoint_auth_methods_supported" => ["client_secret_post", "client_secret_basic"]
  }

  setup %{config: config} do
    openid_configuration =
      Map.merge(@openid_config, Map.delete(config[:openid_configuration], "issuer"))

    config = Keyword.put(config, :openid_configuration, openid_configuration)

    {:ok, config: config}
  end

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Slack.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id="
    assert url =~ "scope=openid+openid+email+profile"
  end

  test "authorize_url/2 with team config", %{config: config} do
    assert {:ok, %{url: url}} = Slack.authorize_url(Keyword.put(config, :team_id, "team_id"))
    assert url =~ "&team=team_id"
  end

  test "callback/2", %{config: config, callback_params: params} do
    claims = Map.put(@id_token_claims, "aud", config[:client_id])
    session_params = Map.put(config[:session_params], :nonce, @id_token_claims["nonce"])
    config = Keyword.put(config, :session_params, session_params)

    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: claims, kid: key["kid"]])

    assert {:ok, %{user: user}} = Slack.callback(config, params)
    assert user == @user
  end
end
