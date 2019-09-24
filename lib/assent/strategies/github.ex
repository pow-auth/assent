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
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.{Config, Strategy.OAuth2}

  @spec default_config(Config.t()) :: Config.t()
  def default_config(_config) do
    [
      site: "https://api.github.com",
      authorize_url: "https://github.com/login/oauth/authorize",
      token_url: "https://github.com/login/oauth/access_token",
      user_url: "/user",
      user_emails_url: "/user/emails",
      authorization_params: [scope: "read:user,user:email"]
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()} | {:error, term()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"      => user["id"],
      "nickname" => user["login"],
      "email"    => user["email"],
      "name"     => user["name"],
      "image"    => user["avatar_url"],
      "urls"     => %{
        "GitHub" => user["html_url"],
        "Blog"   => user["blog"]}}}
  end

  @spec get_user(Config.t(), map()) :: {:ok, map()} | {:error, term()}
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

  defp get_email(config, access_token, user, url) do
    with {:ok, site} <- Config.fetch(config, :site) do
      url             = Helpers.to_url(site, url)
      headers         = OAuth2.authorization_headers(config, access_token)

      :get
      |> Helpers.request(url, nil, headers, config)
      |> Helpers.decode_response(config)
      |> process_get_email_response(user)
    end
  end

  defp process_get_email_response({:ok, %{body: emails}}, user) do
    email = get_primary_email(emails)

    {:ok, Map.put(user, "email", email)}
  end
  defp process_get_email_response({:error, error}, _user), do: {:error, error}

  defp get_primary_email([%{"verified" => true, "primary" => true, "email" => email} | _rest]),
    do: email
  defp get_primary_email(_any), do: nil
end
