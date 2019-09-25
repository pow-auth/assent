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
        private_key_path: "/path/to/key.p8"
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

  You can generate a state by calling:

      {:ok, %{session_params: %{state: state}}} = Assent.Strategy.Apple.authorize_url(config)

  See https://developer.apple.com/documentation/signinwithapplejs/configuring_your_webpage_for_sign_in_with_apple
  for more.
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, JWTAdapter, Strategy.OAuth2.Base}

  @spec default_config(Config.t()) :: Config.t()
  def default_config(_config) do
    [
      site: "https://appleid.apple.com",
      authorize_url: "/auth/authorize",
      token_url: "/auth/token",
      authorization_params: [scope: "email", response_mode: "form_post"],
      auth_method: :client_secret_post
    ]
  end

  @spec callback(Keyword.t(), map()) :: {:ok, %{user: map()}} | {:error, term()}
  def callback(config, params) do
    with {:ok, client_secret} <- gen_client_secret(config) do
      config
      |> Config.put(:client_secret, client_secret)
      |> Base.callback(params, __MODULE__)
    end
  end

  @jwt_expiration_seconds 600

  def gen_client_secret(config) do
    timestamp = :os.system_time(:second)
    config    =
      config
      |> default_config()
      |> Keyword.merge(config)

    with {:ok, site}        <- Config.fetch(config, :site),
         {:ok, client_id}   <- Config.fetch(config, :client_id),
         {:ok, team_id}     <- Config.fetch(config, :team_id),
         :ok                <- ensure_private_key_id(config),
         {:ok, private_key} <- JWTAdapter.load_private_key(config) do

      claims    = %{
        "aud" => site,
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

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, user), do: {:ok, user}

  @spec get_user(Config.t(), map()) :: {:ok, map()}
  def get_user(config, token) do
    with {:ok, jwt} <- Helpers.verify_jwt(token["id_token"], nil, config) do
      {:ok, jwt.claims}
    end
  end
end
