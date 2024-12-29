defmodule Assent.Strategy.Telegram do
  @moduledoc """
  Telegram authorization strategy.

  Supports both
  [Telegram Login Widget](https://core.telegram.org/widgets/login),
  and  [Web Mini App](https://core.telegram.org/bots/webapps) authorizations.

  Note that using the `authorize_url/1` instead of the Telegram JavaScript
  embed script, will send the end-user to the `:return_to` path with a base64
  url encoded JSON string in a URL fragment. This means that it can only be
  accessed client-side, so it must be parsed with JavaScript and resubmitted
  as query params:

      <script type="text/javascript">
        // Function to decode base64 without padding
        function decodeBase64Url(base64Url) {
          let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
          switch (base64.length % 4) {
            case 2: base64 += '=='; break;
            case 3: base64 += '='; break;
          }
          return atob(base64);
        }

        // Parse the hash fragment
        const hash = window.location.hash.substr(1);
        const hashData = hash.split('=')

        if (hashData[0] == "tgAuthResult") {
          const data = JSON.parse(decodeBase64Url(hashData[1]))
          const params = new URLSearchParams(data);

          // Construct the new URL with query parameters
          const newUrl = new URL(window.location.href.split('#')[0]);
          params.forEach((value, key) => {
            newUrl.searchParams.append(key, value);
          });

          // Redirect to the new URL
          window.location.href = newUrl.toString();
        }
      </script>

  Note that the returned user claims can vary widelty, and are depend on the
  authorization channel and user settings.

  ## Configuration

    - `:bot_token` - The telegram bot token, required
    - `:authorization_channel` - The authorization channel, optional, defaults
      to `:login_widget`, may be one of `:login_widget` or `:web_mini_app`
    - `:origin` - The origin URL for `authorize_url/1`, required
    - `:return_to` - The return URL for `authorize_url/1`, required

  ## Usage

  ### Login Widget

  The JavaScript Widget can be implemented with:

      <script async
        src="https://telegram.org/js/telegram-widget.js?22"
        data-telegram-login="REPLACE_WITH_BOT_USERNAME"
        data-auth-url="REPLACE_WITH_CALLBACK_URL"></script>

  Configuration should have:

      config = [
        bot_token: "YOUR_FULL_BOT_TOKEN"
      ]

  Note that if a user declines to authorize access, you have to handle it
  client-side with JavaScript.

  ### Web Mini App

      config = [
        bot_token: "YOUR_FULL_BOT_TOKEN",
        authorization_channel: :web_mini_app
      ]

  For the Web Mini App authorization, the strategy expects the original
  `initData` query param to be passed in as-is.
  """

  @behaviour Assent.Strategy

  alias Assent.{CallbackError, Strategy}

  @auth_ttl_seconds 60
  @web_mini_app :web_mini_app
  @login_widget :login_widget

  @impl Assent.Strategy
  @spec authorize_url(Keyword.t()) :: {:ok, %{url: binary()}} | {:error, term()}
  def authorize_url(config) do
    with {:ok, bot_token} <- Assent.fetch_config(config, :bot_token),
         {:ok, origin} <- Assent.fetch_config(config, :origin),
         {:ok, return_to} <- Assent.fetch_config(config, :return_to) do
      [bot_id | _rest] = String.split(bot_token, ":")

      query =
        URI.encode_query(
          bot_id: bot_id,
          origin: origin,
          return_to: return_to,
          request_access: "read",
          embed: "0"
        )

      {:ok, %{url: "https://oauth.telegram.org/auth?#{query}"}}
    end
  end

  @impl Assent.Strategy
  @spec callback(Keyword.t(), map()) :: {:ok, %{user: map()} | {:error, term()}}
  def callback(config, params) do
    with {:ok, authorization_channel} <- fetch_authorization_channel(config),
         {:ok, {hash, params}} <- split_hash_params(config, params, authorization_channel),
         :ok <- verify_ttl(config, params),
         {:ok, secret} <- generate_token_signature(config, authorization_channel),
         :ok <- verify_hash(secret, hash, params),
         {:ok, user} <- normalize(params, config) do
      {:ok, %{user: user}}
    end
  end

  defp fetch_authorization_channel(config) do
    case Keyword.get(config, :authorization_channel, @login_widget) do
      @login_widget ->
        {:ok, @login_widget}

      @web_mini_app ->
        {:ok, @web_mini_app}

      other ->
        {:error,
         CallbackError.exception(
           message: "Invalid `:authorization_channel` value: #{inspect(other)}"
         )}
    end
  end

  defp split_hash_params(_config, params, @login_widget) do
    with {:ok, hash} <- Assent.fetch_param(params, "hash") do
      {:ok, {hash, Map.delete(params, "hash")}}
    end
  end

  defp split_hash_params(config, params, @web_mini_app) do
    with {:ok, init_data} <- Assent.fetch_param(params, "init_data") do
      split_hash_params(config, URI.decode_query(init_data), @login_widget)
    end
  end

  defp generate_token_signature(config, @login_widget) do
    case Assent.fetch_config(config, :bot_token) do
      {:ok, bot_token} -> {:ok, :crypto.hash(:sha256, bot_token)}
      {:error, error} -> {:error, error}
    end
  end

  defp generate_token_signature(config, @web_mini_app) do
    case Assent.fetch_config(config, :bot_token) do
      {:ok, bot_token} -> {:ok, :crypto.mac(:hmac, :sha256, "WebAppData", bot_token)}
      {:error, error} -> {:error, error}
    end
  end

  defp verify_ttl(_config, params) do
    with {:ok, auth_date} <- Assent.fetch_param(params, "auth_date") do
      auth_timestamp = (is_binary(auth_date) && String.to_integer(auth_date)) || auth_date

      DateTime.utc_now()
      |> DateTime.to_unix(:second)
      |> Kernel.-(auth_timestamp)
      |> Kernel.<=(@auth_ttl_seconds)
      |> case do
        true -> :ok
        false -> {:error, CallbackError.exception(message: "Authorization request has expired")}
      end
    end
  end

  defp verify_hash(secret, hash, params) do
    data =
      params
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)
      |> Enum.sort()
      |> Enum.join("\n")

    data_hash =
      :hmac
      |> :crypto.mac(:sha256, secret, data)
      |> Base.encode16(case: :lower)

    case Assent.constant_time_compare(hash, data_hash) do
      true ->
        :ok

      false ->
        {:error, CallbackError.exception(message: "Authorization request has an invalid hash")}
    end
  end

  defp normalize(%{"user" => user} = params, config) do
    with {:ok, user_params} <- Strategy.decode_json(user, config) do
      params
      |> Map.delete("user")
      |> Map.merge(user_params)
      |> normalize(config)
    end
  end

  defp normalize(%{"id" => id} = params, config) when is_binary(id) do
    normalize(%{params | "id" => String.to_integer(id)}, config)
  end

  defp normalize(params, _config) do
    Strategy.normalize_userinfo(
      %{
        "sub" => params["id"],
        "given_name" => params["first_name"],
        "family_name" => params["last_name"],
        "preferred_username" => params["username"],
        "picture" => params["photo_url"],
        "locale" => params["language_code"]
      },
      Map.take(params, ~w(is_bot is_premium added_to_attachment_menu allows_write_to_pm))
    )
  end
end
