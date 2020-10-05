defmodule Assent.Strategy.Github do
  @moduledoc """
  Github OAuth 2.0 strategy.

  ## Configuration

  - `:user_emails_url` - The API path or URL to fetch e-mails from, defaults to `/user/emails`

  See `Assent.Strategy.OAuth2` for more.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]

  See `Assent.Strategy.OAuth2` for more.
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, Strategy.OAuth2}

  @impl true
  def default_config(_config) do
    [
      site: "https://api.github.com",
      authorize_url: "https://github.com/login/oauth/authorize",
      token_url: "https://github.com/login/oauth/access_token",
      user_url: "/user",
      user_emails_url: "/user/emails",
      authorization_params: [scope: "read:user,user:email"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok, %{
      "sub"                => user["id"],
      "name"               => user["name"],
      "preferred_username" => user["login"],
      "profile"            => user["html_url"],
      "picture"            => user["avatar_url"],
      "email"              => user["email"],
      "email_verified"     => user["email_verified"]
    }}
  end

  @impl true
  def get_user(config, access_token) do
    case Config.fetch(config, :user_emails_url) do
      {:ok, user_emails_url} -> get_user(config, access_token, user_emails_url)
      {:error, error}        -> {:error, error}
    end
  end

  defp get_user(config, access_token, url) do
    config
    |> OAuth2.get_user(access_token)
    |> case do
      {:ok, user}     -> get_email(config, access_token, user, url)
      {:error, error} -> {:error, error}
    end
  end

  defp get_email(config, token, user, url) do
    config
    |> OAuth2.get(token, url)
    |> process_get_email_response(user)
  end

  defp process_get_email_response({:ok, %{body: emails}}, user) do
    {email, verified} = get_primary_email(emails)

    {:ok, Map.merge(user, %{"email" => email, "email_verified" => verified})}
  end
  defp process_get_email_response({:error, error}, _user), do: {:error, error}

  defp get_primary_email([%{"verified" => verified, "primary" => true, "email" => email} | _rest]),
    do: {email, verified}
  defp get_primary_email([_ | rest]), do: get_primary_email(rest)
  defp get_primary_email(_any), do: {nil, false}
end
