defmodule Twitch do
  use Assent.Strategy.OAuth2.Base
  alias Assent.{Config, Strategy.OAuth2, HTTPAdapter.HTTPResponse, RequestError}

  @impl true
  def default_config(_config) do
    [
      # `:base_url` will be used for any paths below
      base_url: "https://api.twitch.tv/helix",
      # Definining an absolute URI overrides the `:base_url`
      authorize_url: "https://id.twitch.tv/oauth2/authorize",
      token_url: "https://id.twitch.tv/oauth2/token",
      user_url: "/users",
      authorization_params: [scope: "user:read:email"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {
      :ok,
      # Conformed to https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1
      %{
        "sub" => user["id"],
        "name" => user["login"],
        "nickname" => user["display_name"],
        # TODO: What to do about users that used their phone to register at twitch?
        # also email doesn't need to be verified.
        "email" => user["email"],
        "profile" => profile(user),
        "picture" => user["profile_image_url"]
      }
    }
  end

  @impl true
  def fetch_user(config, token, params \\ [], headers \\ []) do
    with {:ok, user_url} <- Config.fetch(config, :user_url),
         {:ok, client_id} <- Config.fetch(config, :client_id) do
      headers = headers ++ [{"Client-ID", client_id}]

      config
      |> OAuth2.request(token, :get, user_url, params, headers)
      |> process_user_response()
    end
  end

  defp process_user_response({:ok, %HTTPResponse{status: 200, body: %{"data" => [user]}}}),
    do: {:ok, user}

  defp process_user_response({:error, %HTTPResponse{status: 401} = response}),
    do: {:error, RequestError.exception(message: "Unauthorized token", response: response)}

  defp profile(%{"login" => name}) do
    "https://www.twitch.tv/#{name}"
  end
end
