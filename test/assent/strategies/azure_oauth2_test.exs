defmodule Assent.Strategy.AzureOAuth2Test do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.AzureOAuth2

  @id_token "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctODkwYS0yNzRhNzJhNzMwOWUiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83ZmU4MTQ0Ny1kYTU3LTQzODUtYmVjYi02ZGU1N2YyMTQ3N2UvIiwiaWF0IjoxMzg4NDQwODYzLCJuYmYiOjEzODg0NDA4NjMsImV4cCI6MTM4ODQ0NDc2MywidmVyIjoiMS4wIiwidGlkIjoiN2ZlODE0NDctZGE1Ny00Mzg1LWJlY2ItNmRlNTdmMjE0NzdlIiwib2lkIjoiNjgzODlhZTItNjJmYS00YjE4LTkxZmUtNTNkZDEwOWQ3NGY1IiwidXBuIjoiZnJhbmttQGNvbnRvc28uY29tIiwidW5pcXVlX25hbWUiOiJmcmFua21AY29udG9zby5jb20iLCJzdWIiOiJKV3ZZZENXUGhobHBTMVpzZjd5WVV4U2hVd3RVbTV5elBtd18talgzZkhZIiwiZmFtaWx5X25hbWUiOiJNaWxsZXIiLCJnaXZlbl9uYW1lIjoiRnJhbmsifQ."
  @user %{
    "uid" => "JWvYdCWPhhlpS1Zsf7yYUxShUwtUm5yzPmw_-jX3fHY",
    "name" => "Frank Miller",
    "first_name" => "Frank",
    "last_name" => "Miller",
    "email" => "frankm@contoso.com"
  }

  describe "authorize_url/2" do
    test "generates url", %{config: config} do
      assert {:ok, %{url: url}} = AzureOAuth2.authorize_url(config)
      assert url =~ "/common/oauth2/authorize?client_id="
    end

    test "generates url with tenant id", %{config: config} do
      config = Keyword.put(config, :tenant_id, "8eaef023-2b34-4da1-9baa-8bc8c9d6a490")

      assert {:ok, %{url: url}} = AzureOAuth2.authorize_url(config)
      assert url =~ "/8eaef023-2b34-4da1-9baa-8bc8c9d6a490/oauth2/authorize?client_id="
    end
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    expect_oauth2_access_token_request(bypass, params: %{access_token: "access_token", id_token: @id_token}, uri: "/common/oauth2/token")

    assert {:ok, %{user: user}} = AzureOAuth2.callback(config, params)
    assert user == @user
  end
end
