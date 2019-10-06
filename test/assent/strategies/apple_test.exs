defmodule Assent.Strategy.AppleTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Apple

  @client_id "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039"
  @team_id "app.test.client"
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
  @id_token "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiYXBwLnRlc3QuY2xpZW50IiwiZXhwIjoxNTY1ODEwNjgyLCJpYXQiOjE1NjU4MTAwODIsInN1YiI6IjAwMTQ3My5mZTZmNmY4M2JmNGI4ZTQ1OTBhYWNiYWJkY2I4NTk4YmQwLjIwMzkiLCJjX2hhc2giOiJoYXNoIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdXRoX3RpbWUiOjE1NjU4MTAwODJ9.m9NfZG_OcdsoTh0C5AAv_zv8OAtCpf67QhgNANSYY0bXZD4wYfHROSzvKUKs3zsMY_3liV15B4e-fad_6hO2ug"
  @user %{
    "email" => "john.doe@example.com",
    "email_verified" => true,
    "sub" => "001473.fe6f6f83bf4b8e4590aacbabdcb8598bd0.2039"
  }

  setup context do
    config = Keyword.merge(context[:config], [
      client_id: @client_id,
      team_id: @team_id,
      private_key_id: @private_key_id,
      private_key: @private_key
    ])

    {:ok, %{context | config: config}}
  end


  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Apple.authorize_url(config)
    assert url =~ "/auth/authorize"
    assert url =~ "response_mode=form_post"
    assert url =~ "scope=email"
  end

  if :crypto.supports()[:curves] do
    test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
      expect_oauth2_access_token_request(bypass, [params: %{access_token: "access_token", id_token: @id_token}, uri: "/auth/token"], fn _conn, params ->
        assert {:ok, jwt} = Assent.JWTAdapter.AssentJWT.verify(params["client_secret"], @public_key, json_library: Jason)
        assert jwt.header["alg"] == "ES256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == @private_key_id
        assert jwt.claims["iss"] == @team_id
        assert jwt.claims["sub"] == @client_id
        assert jwt.claims["aud"] == "http://localhost:#{bypass.port}"
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      assert {:ok, %{user: user}} = Apple.callback(config, params)
      assert user == @user
    end
  else
    IO.warn("No support curve algorithms, can't test #{__MODULE__}")
  end
end
