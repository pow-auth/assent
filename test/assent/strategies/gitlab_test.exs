defmodule Assent.Strategy.GitlabTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Gitlab

  # From running GitLab in local
  @id_token_claims %{
    "iss" => "http://localhost",
    "sub" => "1",
    "aud" => "4843ae8973e91d7f63baf626a88e221648d8839d0edee5878c9f1535f6930a1a",
    "exp" => :os.system_time(:second) + 60,
    "iat" => :os.system_time(:second),
    "auth_time" => :os.system_time(:second),
    "sub_legacy" => "71404f201852be9e557f9a3d85724711a2a6a09959beaf1450cc4f548a8182bc",
    "name" => "Administrator",
    "nickname" => "root",
    "preferred_username" => "root",
    "email" => "gitlab_admin_d391ea@example.com",
    "email_verified" => true,
    "profile" => "http://localhost/root",
    "picture" =>
      "https://www.gravatar.com/avatar/261647effda628b0ddac771c741d5165af4590157d740ff427ca89bd2a11b82c?s=80&d=identicon",
    "groups_direct" => []
  }
  @user %{
    "name" => "Administrator",
    "preferred_username" => "root",
    "sub" => "1",
    "email" => "gitlab_admin_d391ea@example.com",
    "email_verified" => true,
    "groups_direct" => [],
    "nickname" => "root",
    "picture" =>
      "https://www.gravatar.com/avatar/261647effda628b0ddac771c741d5165af4590157d740ff427ca89bd2a11b82c?s=80&d=identicon",
    "profile" => "http://localhost/root",
    "sub_legacy" => "71404f201852be9e557f9a3d85724711a2a6a09959beaf1450cc4f548a8182bc"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Gitlab.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id=id"
    assert url =~ "scope=openid+email+profile"
  end

  test "callback/2", %{config: config, callback_params: params} do
    openid_config =
      Map.put(config[:openid_configuration], "token_endpoint_auth_methods_supported", [
        "client_secret_post"
      ])

    config =
      Keyword.merge(config,
        openid_configuration: openid_config,
        client_id: "4843ae8973e91d7f63baf626a88e221648d8839d0edee5878c9f1535f6930a1a"
      )

    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: @id_token_claims, kid: key["kid"]])

    assert {:ok, %{user: user}} = Gitlab.callback(config, params)
    assert user == @user
  end
end
