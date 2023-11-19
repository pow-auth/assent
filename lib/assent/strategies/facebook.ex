defmodule Assent.Strategy.Facebook do
  @moduledoc """
  Facebook OAuth 2.0 strategy.

  The Facebook user endpoint does not provide data on email verification, email
  is considered unverified. More here:
  https://developers.facebook.com/docs/facebook-login/multiple-providers#postfb1

  ## Configuration

  - `:user_url_request_fields` - The fields for the resource, defaults to
    `email,name,first_name,last_name,middle_name,link`

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]

  See `Assent.Strategy.OAuth2` for more.

  ## With JS SDK

  You can use the JS SDK instead of handling it through `auhorize_url/2`. All
  you have to do is to set up you HTML page with the following way:

      <fb:login-button scope="[SCOPES]" onlogin="checkLoginState();">
      </fb:login-button>
      <div id="status">
      </div>

      <script>
        function checkLoginState() {
          FB.getLoginStatus(function(response) {
            let signedRequest = response.authResponse.signedRequest
            let encodedPayload = atob(signedRequest.split('.')[1])
            let payload = JSON.parse(encodedPayload)

            window.location.href = '<%= @redirect_uri %>?&code=' + encodeURI(payload.code)
          });
        }

        window.fbAsyncInit = function() {
          FB.init({
            appId   : '[CLIENT_ID]',
            cookie  : true, // required for server to pick up session
            version : 'v6.0',
            xfbml   : true
          });
        };
      </script>
      <script async defer src="https://connect.facebook.net/en_US/sdk.js"></script>

  In the above, the signed request is decoded and the authorization code is
  fetched from it. The `@redirect_uri` is the callback URL.

  You have to use an empty `redirect_uri` for the callback:

      {:ok, %{user: user, token: token}} =
        config
        |> Assent.Config.put(:redirect_uri, "")
        |> Assent.Strategy.Facebook.callback(params)
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, Strategy.OAuth2}

  @api_version "4.0"

  @impl true
  def default_config(_config) do
    [
      base_url: "https://graph.facebook.com/v#{@api_version}",
      authorize_url: "https://www.facebook.com/v#{@api_version}/dialog/oauth",
      token_url: "/oauth/access_token",
      user_url: "/me",
      authorization_params: [scope: "email"],
      user_url_request_fields: "email,name,first_name,last_name,middle_name,link",
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(config, user) do
    with {:ok, base_url} <- Config.fetch(config, :base_url) do
      {:ok,
       %{
         "sub" => user["id"],
         "name" => user["name"],
         "given_name" => user["first_name"],
         "middle_name" => user["middle_name"],
         "family_name" => user["last_name"],
         "profile" => user["link"],
         "picture" => picture_url(base_url, user),
         "email" => user["email"]
       }}
    end
  end

  defp picture_url(base_url, user) do
    "#{base_url}/#{user["id"]}/picture"
  end

  @impl true
  def fetch_user(config, access_token) do
    with {:ok, fields} <- Config.fetch(config, :user_url_request_fields),
         {:ok, client_secret} <- Config.fetch(config, :client_secret) do
      params = [
        appsecret_proof: appsecret_proof(access_token, client_secret),
        fields: fields,
        access_token: access_token["access_token"]
      ]

      OAuth2.fetch_user(config, access_token, params)
    end
  end

  defp appsecret_proof(access_token, client_secret) do
    :hmac
    |> :crypto.mac(:sha256, client_secret, access_token["access_token"])
    |> Base.encode16(case: :lower)
  end
end
