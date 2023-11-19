defmodule Assent.Strategy.Apple do
  @moduledoc """
  Apple Sign In OAuth 2.0 strategy.

  You'll need to collect the 10-char long Team ID, the Services ID, the 10-char
  Key ID and download the private key from the portal. Save the private key to
  an accessible folder, or alternatively set `:private_key` with the content of
  the private key.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_SERVICES_ID",
        team_id: "REPLACE_WITH_TEAM_ID",
        private_key_id: "REPLACE_WITH_PRIVATE_KEY_ID",
        private_key_path: "/path/to/private_key.p8",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  ## With JS SDK

  You can use the JS SDK instead of handling it through `auhorize_url/2`. All you
  have to do is to set up you HTML page with the following way:

      <html>
        <head>
            <meta name="appleid-signin-client-id" content="[CLIENT_ID]">
            <meta name="appleid-signin-scope" content="[SCOPES]">
            <meta name="appleid-signin-redirect-uri" content="[REDIRECT_URI]">
            <meta name="appleid-signin-state" content="[STATE]">
        </head>
        <body>
            <div id="appleid-signin" data-color="black" data-border="true" data-type="sign in"></div>
            <script type="text/javascript" src="https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js"></script>
        </body>
      </html>

  You can get the state by generating the session params using the
  `authorize_url/2`:

      {:ok, %{session_params: session_params}} = Assent.Strategy.Apple.authorize_url(config)

  Use the `session_params[:state]` value for `[STATE]`. The callback phase
  would be identical to how it's explained in the [README](README.md).

  See https://developer.apple.com/documentation/signinwithapplejs/configuring_your_webpage_for_sign_in_with_apple
  for more.
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.{Config, JWTAdapter, Strategy.OIDC, Strategy.OIDC.Base}

  @impl true
  def default_config(config) do
    base_url = Config.get(config, :base_url, "https://appleid.apple.com")

    [
      base_url: base_url,
      openid_configuration: %{
        "issuer" => "https://appleid.apple.com",
        "authorization_endpoint" => base_url <> "/auth/authorize",
        "token_endpoint" => base_url <> "/auth/token",
        "jwks_uri" => base_url <> "/auth/keys",
        "token_endpoint_auth_methods_supported" => ["client_secret_post"]
      },
      authorization_params: [scope: "email", response_mode: "form_post"],
      client_authentication_method: "client_secret_post",
      openid_default_scope: ""
    ]
  end

  @doc false
  @impl true
  def callback(config, params) do
    with {:ok, client_secret} <- gen_client_secret(config),
         {:ok, user_info} <- decode_user_params(config, params) do
      config
      |> Config.put(:client_secret, client_secret)
      |> Config.put(:user, user_info)
      |> Base.callback(params, __MODULE__)
    end
  end

  @jwt_expiration_seconds 600

  defp gen_client_secret(config) do
    timestamp = :os.system_time(:second)

    config =
      config
      |> default_config()
      |> Keyword.merge(config)

    with {:ok, base_url} <- Config.fetch(config, :base_url),
         {:ok, client_id} <- Config.fetch(config, :client_id),
         {:ok, team_id} <- Config.fetch(config, :team_id),
         :ok <- ensure_private_key_id(config),
         {:ok, private_key} <- JWTAdapter.load_private_key(config) do
      claims = %{
        "aud" => base_url,
        "iss" => team_id,
        "sub" => client_id,
        "iat" => timestamp,
        "exp" => timestamp + @jwt_expiration_seconds
      }

      Helpers.sign_jwt(claims, "ES256", private_key, config)
    end
  end

  defp ensure_private_key_id(config) do
    with {:ok, _private_key_id} <- Config.fetch(config, :private_key_id) do
      :ok
    end
  end

  defp decode_user_params(config, %{"user" => user}), do: Helpers.decode_json(user, config)
  defp decode_user_params(_config, %{}), do: {:ok, %{}}

  @impl true
  def fetch_user(config, token) do
    with {:ok, user} <- OIDC.fetch_user(config, token),
         {:ok, user_info} <- Config.fetch(config, :user) do
      {:ok, Map.merge(user, user_info)}
    end
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["sub"],
       "email" => user["email"],
       "email_verified" => true,
       "given_name" => Map.get(user, "name", %{})["firstName"],
       "family_name" => Map.get(user, "name", %{})["lastName"]
     }}
  end
end
