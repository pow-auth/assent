defmodule Assent.Strategy.VK do
  @moduledoc """
  VK.com OAuth 2.0 strategy.

  The VK token endpoint does not provide data on email verification, email is
  considered unverified.

  ## Configuration

  - `:user_url_params` - Parameters to send along with the user fetch request,
    optional, defaults to `[]`

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, Strategy.OAuth2}

  @profile_fields ["uid", "first_name", "last_name", "photo_200", "screen_name"]
  @url_params [fields: Enum.join(@profile_fields, ","), v: "5.69", https: "1"]

  @impl true
  def default_config(config) do
    params = Config.get(config, :user_url_params, [])
    user_url_params = Config.merge(@url_params, params)

    [
      base_url: "https://api.vk.com",
      authorize_url: "https://oauth.vk.com/authorize",
      token_url: "https://oauth.vk.com/access_token",
      user_url: "/method/users.get",
      authorization_params: [scope: "email"],
      user_url_params: user_url_params,
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
     %{
       "sub" => user["id"],
       "given_name" => user["first_name"],
       "family_name" => user["last_name"],
       "picture" => user["photo_200"],
       "email" => user["email"]
     }}
  end

  @impl true
  def fetch_user(config, token) do
    params =
      config
      |> Config.get(:user_url_params, [])
      |> Config.put(:access_token, token["access_token"])

    config
    |> OAuth2.fetch_user(token, params)
    |> handle_user_response(token)
  end

  defp handle_user_response({:ok, %{"response" => [user]}}, token) do
    user =
      user
      |> Map.put_new("id", token["user_id"])
      |> Map.put_new("email", token["email"])

    {:ok, user}
  end

  defp handle_user_response({:ok, user}, _token) do
    {
      :error,
      RuntimeError.exception("""
      Retrieved an invalid response fetching VK user.

      User response:
      #{inspect(user)}
      """)
    }
  end

  defp handle_user_response({:error, error}, _token) do
    {:error, error}
  end
end
