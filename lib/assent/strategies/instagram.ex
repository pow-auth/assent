defmodule Assent.Strategy.Instagram do
  @moduledoc """
  Instagram OAuth 2.0 strategy.

  ## Usage

      config = [
        client_id: "REPLACE_WITH_CLIENT_ID",
        client_secret: "REPLACE_WITH_CLIENT_SECRET"
      ]
  """
  use Assent.Strategy.OAuth2.Base

  alias Assent.Config

  @spec default_config(Config.t()) :: Keyword.t()
  def default_config(_config) do
    [
      site: "https://api.instagram.com",
      authorization_params: [scope: "basic"],
      auth_method: :client_secret_post
    ]
  end

  @spec normalize(Config.t(), map()) :: {:ok, map()}
  def normalize(_config, user) do
    {:ok, %{
      "uid"      => user["id"],
      "name"     => user["full_name"],
      "image"    => user["profile_picture"],
      "nickname" => user["username"]}}
  end

  @spec get_user(Config.t(), map()) :: {:ok, map()}
  def get_user(_config, token) do
    {:ok, token["user"]}
  end
end
