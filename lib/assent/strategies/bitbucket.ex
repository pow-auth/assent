defmodule Assent.Strategy.Bitbucket do
  @moduledoc """
  Bitbucket Cloud OAuth 2.0 strategy.

  ## Configuration

  - `:user_emails_url` - The API path or URL to fetch e-mails from, defaults to `/user/emails`

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CONSUMER_KEY",
        client_secret: "REPLACE_WITH_CONSUMER_SECRET",
        redirect_uri: "http://localhost:4000/auth/callback"
      ]
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.Strategy.OAuth2

  @impl true
  def default_config(_config) do
    [
      base_url: "https://api.bitbucket.org/2.0",
      authorize_url: "https://bitbucket.org/site/oauth2/authorize",
      token_url: "https://bitbucket.org/site/oauth2/access_token",
      user_url: "/user",
      user_emails_url: "/user/emails",
      authorization_params: [scope: "account email"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    avatar_url = user["links"]["avatar"] && user["links"]["avatar"]["href"]

    {:ok,
     %{
       "sub" => user["account_id"],
       "name" => user["display_name"],
       "nickname" => user["nickname"],
       "preferred_username" => user["username"],
       "picture" => avatar_url,
       "email" => user["email"],
       "email_verified" => user["email_verified"]
     }}
  end

  @impl true
  def fetch_user(config, access_token) do
    with {:ok, user_emails_url} <- Assent.fetch_config(config, :user_emails_url),
         {:ok, user} <- OAuth2.fetch_user(config, access_token) do
      fetch_email(config, access_token, user, user_emails_url)
    end
  end

  defp fetch_email(config, token, user, url) do
    config
    |> OAuth2.request(token, :get, url)
    |> process_email_response(user)
  end

  defp process_email_response({:ok, %{body: %{"values" => emails}}}, user) do
    {email, verified} = get_primary_email(emails)

    {:ok, Map.merge(user, %{"email" => email, "email_verified" => verified})}
  end

  defp process_email_response({:error, error}, _user), do: {:error, error}

  defp get_primary_email([
         %{"is_confirmed" => verified, "is_primary" => true, "email" => email} | _rest
       ]),
       do: {email, verified}

  defp get_primary_email([_ | rest]), do: get_primary_email(rest)
  defp get_primary_email(_any), do: {nil, false}
end
