defmodule Assent.Strategy.AzureOAuth2Test do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.AzureOAuth2

  # From https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
  @id_token "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjFMVE16YWtpaGlSbGFfOHoyQkVKVlhlV01xbyJ9.eyJ2ZXIiOiIyLjAiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkL3YyLjAiLCJzdWIiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFJa3pxRlZyU2FTYUZIeTc4MmJidGFRIiwiYXVkIjoiNmNiMDQwMTgtYTNmNS00NmE3LWI5OTUtOTQwYzc4ZjVhZWYzIiwiZXhwIjoxNTM2MzYxNDExLCJpYXQiOjE1MzYyNzQ3MTEsIm5iZiI6MTUzNjI3NDcxMSwibmFtZSI6IkFiZSBMaW5jb2xuIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWJlTGlAbWljcm9zb2Z0LmNvbSIsIm9pZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC02NmYzLTMzMzJlY2E3ZWE4MSIsInRpZCI6IjMzMzgwNDBkLTZjNjctNGM1Yi1iMTEyLTM2YTMwNGI2NmRhZCIsIm5vbmNlIjoiMTIzNTIzIiwiYWlvIjoiRGYyVVZYTDFpeCFsTUNXTVNPSkJjRmF0emNHZnZGR2hqS3Y4cTVnMHg3MzJkUjVNQjVCaXN2R1FPN1lXQnlqZDhpUURMcSFlR2JJRGFreXA1bW5PcmNkcUhlWVNubHRlcFFtUnA2QUlaOGpZIn0.1AFWW-Ck5nROwSlltm7GzZvDwUkqvhSQpm55TQsmVo9Y59cLhRXpvB8n-55HCr9Z6G_31_UbeUkoz612I2j_Sm9FFShSDDjoaLQr54CreGIJvjtmS3EkK9a7SJBbcpL1MpUtlfygow39tFjY7EVNW9plWUvRrTgVk7lYLprvfzw-CIqw3gHC-T7IK_m_xkr08INERBtaecwhTeN4chPC4W3jdmw_lIxzC48YoQ0dB1L9-ImX98Egypfrlbm0IBL5spFzL6JDZIRRJOu8vecJvj1mq-IUhGt0MacxX8jdxYLP-KUu2d9MbNKpCKJuZ7p8gwTL5B7NlUdh_dmSviPWrw"
  @user %{
    "name" => "Abe Lincoln",
    "preferred_username" => "AbeLi@microsoft.com",
    "sub" => "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"
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
    expect_oauth2_access_token_request(bypass, [params: %{access_token: "access_token", id_token: @id_token}, uri: "/common/oauth2/token"], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)

    assert {:ok, %{user: user}} = AzureOAuth2.callback(config, params)
    assert user == @user
  end
end
