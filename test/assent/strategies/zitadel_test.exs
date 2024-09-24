defmodule Assent.Strategy.ZitadelTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Zitadel
  alias Plug.Conn

  @private_key_id "key_id"
  @private_key """
  -----BEGIN PRIVATE KEY-----
  MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
  OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
  1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
  -----END PRIVATE KEY-----
  """
  @public_key """
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
  q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
  -----END PUBLIC KEY-----
  """

  @client_id "3425235252@nameofproject"
  @resource_id "3425296767"
  @id_token_claims %{
    "iss" => "https://zitadel.cloud",
    "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039",
    "aud" => [@client_id, @resource_id],
    "exp" => :os.system_time(:second) + 5 * 60,
    "iat" => :os.system_time(:second),
    "email" => "john.doe@example.com",
    "nonce" => "123523"
  }
  @user %{
    "email" => "john.doe@example.com",
    "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039"
  }

  setup %{config: config, callback_params: callback_params} do
    openid_configuration = %{
      "issuer" => "https://zitadel.cloud",
      "authorization_endpoint" => TestServer.url("/oauth/v2/authorize"),
      "token_endpoint" => TestServer.url("/oauth/v2/token"),
      "userinfo_endpoint" => TestServer.url("/userinfo"),
      "jwks_uri" => TestServer.url("/jwks_uri.json"),
      "token_endpoint_auth_methods_supported" => ["client_secret_post", "none"]
    }

    config = Keyword.put(config, :openid_configuration, openid_configuration)
    config = Keyword.put(config, :client_authentication_method, "none")

    callback_params =
      Map.merge(callback_params, %{"code" => "123523", "state" => "456856"})

    {:ok, config: config, callback_params: callback_params}
  end

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Zitadel.authorize_url(config)
    assert url =~ "/oauth/v2/authorize?client_id=id"
    assert url =~ "scope=openid+email"
    assert url =~ "response_type=code"
  end

  test "authorize_url/2 with PKCE", %{config: config} do
    assert {:ok, %{url: url}} = Zitadel.authorize_url(config ++ [code_verifier: true, nonce: true])
    assert url =~ "/oauth/v2/authorize?client_id=id"
    assert url =~ "scope=openid+email"
    assert url =~ "response_type=code"
    assert url =~ "code_challenge="
    assert url =~ "nonce="
    assert url =~ "state="
    assert url =~ "code_challenge_method=S256"
    assert not String.match?(url, ~r/code_verifier/)
  end

  test "callback/2", %{config: config, callback_params: params} do
    openid_config =
      config[:openid_configuration]

    session_params = %{nonce: "123523", state: "456856", code_verifier: "ttt333qqq000"}

    config =
      Keyword.merge(config,
        openid_configuration: openid_config,
        client_id: @client_id,
        resource_id: @resource_id,
        session_params: session_params
      )

    [key | _rest] = expect_oidc_jwks_uri_request()

    expect_oidc_access_token_request(
      id_token_opts: [claims: @id_token_claims, kid: key["kid"]],
      uri: "/oauth/v2/token"
    )

    assert {:ok, %{user: user}} = Zitadel.callback(config, params)
    assert user == @user
  end

  test "authenticate_api/1", %{config: config} do
    config =
      Keyword.merge(config,
        client_id: @client_id,
        resource_id: @resource_id,
        private_key: @private_key,
        private_key_id: @private_key_id,
        issuer: "https://zitadel.cloud"
      )

    expect_api_access_token_request()

    assert {:ok, %{"access_token" => "access_token"}} == Zitadel.authenticate_api(config)
  end

  @spec expect_api_access_token_request(Keyword.t(), function() | nil) :: :ok
  defp expect_api_access_token_request(opts \\ [], assert_fn \\ nil) do
    access_token = Keyword.get(opts, :access_token, "access_token")
    token_params = Keyword.get(opts, :params, %{access_token: access_token})
    uri = Keyword.get(opts, :uri, "/oauth/v2/token")
    status_code = Keyword.get(opts, :status_code, 200)

    TestServer.add(uri,
      via: :post,
      to: fn conn ->
        {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        if assert_fn, do: assert_fn.(conn, params)

        send_json_resp(conn, token_params, status_code)
      end
    )
  end

  defp send_json_resp(conn, body, status_code) do
    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(status_code, Jason.encode!(body))
  end
end
