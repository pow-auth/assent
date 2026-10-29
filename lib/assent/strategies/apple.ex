defmodule Assent.Strategy.Apple do
  @moduledoc """
  Apple Sign In OpenID Connect strategy.

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

  You can use the JS SDK instead of handling it through `authorize_url/1`. All
  you have to do is to set up your HTML page in the following way:

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
  `authorize_url/1`:

      {:ok, %{session_params: session_params}} = Assent.Strategy.Apple.authorize_url(config)

  Use the `session_params[:state]` value for `[STATE]`. The callback phase
  would be identical to how it's explained in the `Assent` docs.

  See the [Sign in with Apple JS
  documentation](https://developer.apple.com/documentation/signinwithapplejs/configuring_your_webpage_for_sign_in_with_apple)
  for more.

  ## User info

  The user info may include these claims specific to Apple:

    * `is_private_email` - indicates whether the email that the user shares is
      a proxy address;
    * `real_user_status` - indicates whether the user appears to be a real
      person;
    * `org_id`           - indicates the organization ID associated with the
      user;

  ## Names

  For privacy, Apple [doesn't include](https://developer.apple.com/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server.#Get-the-user-information-and-tokens)
  the user's name in the ID token. Instead, the browser submits it in a `user`
  parameter during initial authorization. This data is unverified and can be
  modified by the end user. If you want to include the name in the user info,
  add this to the config:

      include_unverified_name: true

  Once enabled and if available in the `user` parameter, `given_name` and
  `family_name` fields will be included in the user info.
  """
  use Assent.Strategy.OIDC.Base

  alias Assent.{JWTAdapter, Strategy.OIDC, Strategy.OIDC.Base}

  @impl true
  def default_config(config) do
    base_url = Keyword.get(config, :base_url, "https://appleid.apple.com")

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
      openid_default_scope: nil
    ]
  end

  @doc false
  @impl true
  def callback(config, params) do
    with {:ok, client_secret} <- gen_client_secret(config),
         {:ok, claims} <- fetch_apple_user_claims(config, params),
         config <- Keyword.put(config, :client_secret, client_secret),
         {:ok, response} <- Base.callback(config, params, __MODULE__) do
      {:ok, %{response | user: Map.merge(claims, response.user)}}
    end
  end

  @jwt_expiration_seconds 600

  defp gen_client_secret(config) do
    timestamp = :os.system_time(:second)

    config =
      config
      |> default_config()
      |> Keyword.merge(config)

    with {:ok, base_url} <- Assent.fetch_config(config, :base_url),
         {:ok, client_id} <- Assent.fetch_config(config, :client_id),
         {:ok, team_id} <- Assent.fetch_config(config, :team_id),
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
    with {:ok, _private_key_id} <- Assent.fetch_config(config, :private_key_id) do
      :ok
    end
  end

  defp fetch_apple_user_claims(config, %{"user" => encoded_user}) do
    case Keyword.get(config, :include_unverified_name, false) do
      true -> decode_apple_user_params(config, encoded_user)
      false -> {:ok, %{}}
    end
  end

  defp fetch_apple_user_claims(_config, _params), do: {:ok, %{}}

  @name_claim_types %{
    "given_name" => :binary,
    "family_name" => :binary
  }

  defp decode_apple_user_params(config, encoded_user) do
    case Helpers.decode_json(encoded_user, config) do
      {:ok, %{"name" => name}} when is_map(name) ->
        Helpers.cast_claims(
          %{
            "given_name" => Map.get(name, "firstName"),
            "family_name" => Map.get(name, "lastName")
          },
          @name_claim_types
        )

      {:ok, %{"name" => _invalid}} ->
        raise ArgumentError, "invalid user param, expected name to be a JSON object"

      {:ok, user} when is_map(user) ->
        {:ok, %{}}

      {:ok, _user} ->
        raise ArgumentError, "invalid user param, expected a JSON object"

      {:error, _error} ->
        raise ArgumentError, "invalid user param, expected valid JSON"
    end
  end

  @claim_types %{"is_private_email" => :boolean}

  @impl true
  def fetch_user(config, token) do
    with {:ok, user} <- OIDC.fetch_user(config, token),
         {:ok, extra} <- Helpers.cast_claims(user, @claim_types) do
      {:ok, Map.merge(user, extra)}
    end
  end
end
