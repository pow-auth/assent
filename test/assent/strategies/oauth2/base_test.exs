defmodule Assent.Strategy.OAuth2.BaseTest do
  use Assent.Test.OAuth2TestCase

  defmodule EnvelopeStrategy do
    @moduledoc false
    use Assent.Strategy.OAuth2.Base

    @impl true
    def default_config(_config), do: [auth_method: :client_secret_post, user_url: "/api/user"]

    @impl true
    def normalize(_config, user), do: {:ok, user}

    # Unwrap a non-standard `{"data": {...}}` token-response envelope.
    @impl true
    def normalize_access_token(%{"data" => token}) when is_map(token), do: {:ok, token}
    def normalize_access_token(token), do: {:ok, token}
  end

  describe "callback/2 with normalize_access_token/1" do
    test "unwraps an enveloped token response before it is processed", %{
      config: config,
      callback_params: params
    } do
      # The token endpoint returns the access token wrapped in a `data`
      # envelope — not the OAuth2-standard top-level shape.
      expect_oauth2_access_token_request(
        params: %{"data" => %{"access_token" => "wrapped_token"}}
      )

      expect_oauth2_user_request(%{"id" => "1", "email" => "a@b.example"},
        access_token: "wrapped_token"
      )

      assert {:ok, %{user: user, token: token}} = EnvelopeStrategy.callback(config, params)

      # The wrapped token was unwrapped and used to fetch the user.
      assert token["access_token"] == "wrapped_token"
      assert user["email"] == "a@b.example"
    end

    test "defaults to identity for a standard token response", %{
      config: config,
      callback_params: params
    } do
      # A standard (non-enveloped) token response is unaffected by the default
      # `normalize_access_token/1`.
      expect_oauth2_access_token_request(params: %{"access_token" => "plain_token"})
      expect_oauth2_user_request(%{"id" => "1"}, access_token: "plain_token")

      assert {:ok, %{token: token}} = EnvelopeStrategy.callback(config, params)
      assert token["access_token"] == "plain_token"
    end
  end
end
