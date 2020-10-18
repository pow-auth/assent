defmodule Assent.Strategy.LINETest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.LINE

  # From https://developers.line.biz/en/docs/line-login/integrate-line-login/#verify-id-token
  @id_token elem(Assent.Strategy.sign_jwt(
    %{
      "iss" => "https://access.line.me",
      "sub" => "U1234567890abcdef1234567890abcdef ",
      "aud" => "1234567890",
      "exp" => :os.system_time(:second) + 60,
      "iat" => :os.system_time(:second),
      "nonce" => "0987654asdf",
      "amr" => ["pwd"],
      "name" => "Taro Line",
      "picture" => "https://sample_line.me/aBcdefg123456"
    },
    "HS256",
    "secret",
    []), 1)
  @user %{
    "name" => "Taro Line",
    "picture" => "https://sample_line.me/aBcdefg123456",
    "sub" => "U1234567890abcdef1234567890abcdef "
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = LINE.authorize_url(config)
    assert url =~ "scope=openid+email+profile"
    assert url =~ "response_type=code"
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    openid_config  = Map.merge(config[:openid_configuration], %{"issuer" => "https://access.line.me"})
    session_params = Map.put(config[:session_params], :nonce, "0987654asdf")
    config         = Keyword.merge(config, openid_configuration: openid_config, client_id: "1234567890", session_params: session_params)

    expect_oidc_access_token_request(bypass, id_token: @id_token)

    assert {:ok, %{user: user}} = LINE.callback(config, params)
    assert user == @user
  end
end
