defmodule Assent.Strategy.GoogleTest do
  use Assent.Test.OIDCTestCase

  alias Assent.Strategy.Google

  # From https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
  @id_token_claims %{
    "iss" => "https://accounts.google.com",
    "azp" => "1234987819200.apps.googleusercontent.com",
    "aud" => "1234987819200.apps.googleusercontent.com",
    "sub" => "10769150350006150715113082367",
    "at_hash" => "HK6E_P6Dh8Y93mRNtsDB1Q",
    "hd" => "example.com",
    "email" => "jsmith@example.com",
    "email_verified" => "true",
    "iat" => DateTime.to_unix(DateTime.utc_now()),
    "exp" => DateTime.to_unix(DateTime.utc_now()) + 60,
    "nonce" => "0394852-3190485-2490358"
  }
  @user %{
    "email" => "jsmith@example.com",
    "email_verified" => true,
    "hd" => "example.com",
    "sub" => "10769150350006150715113082367"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Google.authorize_url(config)

    uri = URI.parse(url)

    assert %{"client_id" => "id", "scope" => scope} = URI.decode_query(uri.query)
    assert scope =~ "email profile"
  end

  test "callback/2", %{config: config, callback_params: params} do
    openid_config =
      config[:openid_configuration]
      |> Map.put("issuer", "https://accounts.google.com")
      |> Map.put("token_endpoint_auth_methods_supported", ["client_secret_post"])

    session_params = Map.put(config[:session_params], :nonce, "0394852-3190485-2490358")

    config =
      Keyword.merge(config,
        openid_configuration: openid_config,
        client_id: "1234987819200.apps.googleusercontent.com",
        session_params: session_params
      )

    [key | _rest] = expect_oidc_jwks_uri_request()
    expect_oidc_access_token_request(id_token_opts: [claims: @id_token_claims, kid: key["kid"]])

    assert {:ok, %{user: user}} = Google.callback(config, params)
    assert user == @user
  end
end
