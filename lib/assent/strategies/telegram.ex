defmodule Assent.Strategies.Telegram do
  @moduledoc """
  ### Sign in with Telegram strategy

  As the [Telegram Login Widget](https://core.telegram.org/widgets/login) only supports authentication requests
  via an embedded widget or a JS call, and for the [Web Mini App](https://core.telegram.org/bots/webapps) authentication data is
  sent when a user opens a mini app in Telegram, the strategy does not implement the `authorize_url/1` method.

  The default TTL for the authentication data is 60 seconds. This can be increased by the `max_auth_validity_sec` config key.

  ## Usage

  ### Login Widget

      config = [
        authentication_channel: :login_widget,
        bot_token: "YOUR_FULL_BOT_TOKEN",
        max_auth_validity_sec: 60
      ]


  Please note that in the case of the JavaScript authentication callback, if a user declines to authenticate,
  the `false` response from the Telegram widget library should be handled client-side.

  A basic implementation is described in the Telegram Login Widget docs. A more advanced option without
  an embedded iframe via direct JS call and with custom login button can be found on [Stack Overflow](https://stackoverflow.com/a/63593384/899911).

  The Telegram strategy supports both redirect and function callback options.

  ### Web Mini App

      config = [
        authentication_channel: :web_mini_app,
        bot_token: "YOUR_FULL_BOT_TOKEN",
        max_auth_validity_sec: 60
      ]

  For the Web Mini App authentication, the strategy expects the original `initData` string to be passed in as-is,
  in URL-encoded form, wrapped by a map as the value for the `init_data` key:

      %{ init_data: "original%20initData%20string" }


  ## Possible Response Details

  As Telegram states that the returning claims can vary (marked as `optional`) and heavily depend on the authentication
  channel and user settings, the claims returned from `callback/2` can also vary.

  All fields have been renamed to comply with the OpenID Connect standard, and the `sub` claim is (likely) always present.

  The most complete set of claims looks like this:

      %{
        # Standard OpenID Connect claims
        "sub" => integer(),
        "name" => String.t(),
        "given_name" => String.t(),
        "family_name" => String.t(),
        "preferred_username" => String.t(),
        "picture" => String.t(),
        "locale" => String.t(),

        # Extra claims
        "is_bot" => boolean(),
        "is_premium" => boolean(),
        "added_to_attachment_menu" => boolean(),
        "allows_write_to_pm" => boolean(),
        "authenticated_at" => DateTime.t()
      }


  ### Original Telegram Full Login Success Response for the Login Widget:

      %{
        "id" => integer(),
        "first_name" => String.t(),
        "last_name" => String.t(),
        "username" => String.t(),
        "photo_url" => String.t(),
        "auth_date" => integer(),
        "hash" => String.t()
      }

  ### Original possible Telegram full decoded initData for the Web Mini App:

      %{
        "query_id" => String.t(),
        "user" => %{
          "id" => integer(),
          "is_bot" => boolean(),
          "first_name" => String.t(),
          "last_name" => String.t(),
          "username" => String.t(),
          "language_code" => String.t(),
          "is_premium" => boolean(),
          "added_to_attachment_menu" => boolean(),
          "allows_write_to_pm" => boolean(),
          "photo_url" => String.t()
        },
        "receiver" => %{
          "id" => integer(),
          "is_bot" => boolean(),
          "first_name" => String.t(),
          "last_name" => String.t(),
          "username" => String.t(),
          "language_code" => String.t(),
          "is_premium" => boolean(),
          "added_to_attachment_menu" => boolean(),
          "allows_write_to_pm" => boolean(),
          "photo_url" => String.t()
        },
        "chat" => %{
          "id" => integer(),
          "type" => String.t(),
          "title" => String.t(),
          "username" => String.t(),
          "photo_url" => String.t()
        },
        "chat_type" => String.t(),
        "chat_instance" => String.t(),
        "start_param" => String.t(),
        "can_send_after" => integer(),
        "auth_date" => integer(),
        "hash" => String.t()
      }
      ```
  """

  @behaviour Assent.Strategy

  alias Assent.Strategy
  alias Assent.Config
  alias Assent.CallbackError

  @default_config [
    max_auth_validity_sec: 60
  ]

  @web_app_key "WebAppData"
  @web_mini_app :web_mini_app
  @login_widget :login_widget

  @type login_widget_response :: %{String.t() => String.t()}
  @type mini_app_init_data :: String.t()
  @type mini_app_response ::
          %{init_data: mini_app_init_data()} | %{String.t() => mini_app_init_data()}
  @type response_params :: mini_app_response() | login_widget_response()

  @impl Assent.Strategy
  def authorize_url(_config) do
    {:error, "Telegram does not support direct authorization request, please check docs"}
  end

  @impl Assent.Strategy
  def callback(config, %{"init_data" => init_data} = _response_params),
    do: callback(config, %{init_data: init_data})

  def callback(config, %{} = response_params) do
    config = enrich_config(config)

    with :ok <- do_preflight_checks(config, response_params),
         {:ok, params} <- maybe_convert_init_data(response_params),
         :ok <- check_hash_key(params),
         :ok <- check_auth_date_key(params) do
      authenticate(config, params)
    end
  end

  ### Private part

  defp do_preflight_checks(config, response_params) do
    with {:ok, auth_channel} <- fetch_authentication_channel(config),
         :ok <- check_params_match_channel(response_params, auth_channel) do
      :ok
    end
  end

  defp check_params_match_channel(%{init_data: _}, @login_widget),
    do: cerr(:init_data_with_login_widget)

  defp check_params_match_channel(%{init_data: ""}, @web_mini_app),
    do: cerr(:init_data_empty)

  defp check_params_match_channel(params, @web_mini_app) when not is_map_key(params, :init_data),
    do: cerr(:no_init_data)

  defp check_params_match_channel(%{init_data: init_data}, @web_mini_app)
       when not is_binary(init_data),
       do: cerr(:no_init_data)

  defp check_params_match_channel(_params, _auth_channel), do: :ok

  defp check_hash_key(%{"hash" => _}), do: :ok
  defp check_hash_key(_), do: cerr(:missing_hash_key)

  defp check_auth_date_key(%{"auth_date" => _}), do: :ok
  defp check_auth_date_key(_), do: cerr(:missing_auth_date_key)

  defp maybe_convert_init_data(%{init_data: init_data}), do: {:ok, URI.decode_query(init_data)}
  defp maybe_convert_init_data(response_params), do: {:ok, response_params}

  defp authenticate(config, response_params) do
    with {:ok, bot_token} <- fetch_bot_token(config),
         {:ok, auth_channel} <- fetch_authentication_channel(config),
         secret_key = build_secret_key(auth_channel, bot_token),
         :ok <- verify_authenticity(response_params, secret_key),
         {:ok, max_auth_validity_sec} <- Config.fetch(config, :max_auth_validity_sec),
         {:ok, auth_date} <- date_time_from_unix(response_params["auth_date"]),
         :ok <- verify_ttl(auth_date, max_auth_validity_sec) do
      claims = normalize(response_params, config)
      {:ok, %{user: claims}}
    end
  end

  defp normalize(%{"user" => user} = response_params, config) do
    with {:ok, user_as_map} <- Strategy.decode_json(user, config) do
      response_params
      |> Map.delete("user")
      |> Map.merge(user_as_map)
      |> normalize(config)
    end
  end

  defp normalize(%{"id" => id} = response_params, config) when is_binary(id) do
    normalize(%{response_params | "id" => String.to_integer(id)}, config)
  end

  defp normalize(%{} = response_params, _config) do
    {:ok, authenticated_at} = date_time_from_unix(response_params["auth_date"])

    %{
      # standard OpenID Connect claims
      "sub" => response_params["id"],
      "name" => build_full_name(response_params),
      "given_name" => response_params["first_name"],
      "family_name" => response_params["last_name"],
      "preferred_username" => response_params["username"],
      "picture" => response_params["photo_url"],
      "locale" => response_params["language_code"],
      # extra claims
      "is_bot" => response_params["is_bot"],
      "is_premium" => response_params["is_premium"],
      "added_to_attachment_menu" => response_params["added_to_attachment_menu"],
      "allows_write_to_pm" => response_params["allows_write_to_pm"]
    }
    |> Strategy.prune()
    |> Map.put("authenticated_at", authenticated_at)
  end

  defp verify_authenticity(%{"hash" => provided_hash} = response_params, secret_key) do
    response_params
    |> calculate_actual_hash(secret_key)
    |> case do
      ^provided_hash -> :ok
      _ -> cerr(:authenticity_check_failed)
    end
  end

  defp calculate_actual_hash(response_params, secret_key) do
    data_check_string = build_authenticity_check_string(response_params)

    :hmac
    |> :crypto.mac(:sha256, secret_key, data_check_string)
    |> Base.encode16(case: :lower)
  end

  defp build_secret_key(@login_widget, bot_token),
    do: :crypto.hash(:sha256, bot_token)

  defp build_secret_key(@web_mini_app, bot_token),
    do: :crypto.mac(:hmac, :sha256, @web_app_key, bot_token)

  defp build_authenticity_check_string(response_params) do
    response_params
    |> Map.delete("hash")
    |> Enum.sort_by(fn {key, _value} -> key end)
    |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)
    |> Enum.join("\n")
  end

  defp verify_ttl(%DateTime{} = auth_date, max_auth_validity_sec) do
    DateTime.utc_now()
    |> DateTime.diff(auth_date, :second)
    |> case do
      since when since > max_auth_validity_sec -> cerr(:auth_request_expired)
      future when future < 0 -> cerr(:auth_date_in_future)
      _ -> :ok
    end
  end

  defp date_time_from_unix(unix_time_string) when is_binary(unix_time_string) do
    unix_time_string
    |> Integer.parse()
    |> case do
      {unix_time_int, _} -> date_time_from_unix(unix_time_int)
      _ -> cerr(:invalid_auth_date, details: [auto_date: unix_time_string])
    end
  end

  defp date_time_from_unix(unix_time) do
    unix_time
    |> DateTime.from_unix()
    |> case do
      {:ok, date} -> {:ok, date}
      _ -> cerr(:invalid_auth_date, details: [auto_date: unix_time])
    end
  end

  defp build_full_name(response_params) do
    [
      response_params["first_name"],
      response_params["last_name"]
    ]
    |> Enum.join(" ")
    |> String.trim()
  end

  defp fetch_bot_token(config) do
    config
    |> Config.fetch(:bot_token)
    |> case do
      {:ok, bot_token} when is_binary(bot_token) -> {:ok, bot_token}
      _ -> cerr(:invalid_bot_token)
    end
  end

  @auth_channels [@login_widget, @web_mini_app]

  defp fetch_authentication_channel(config) do
    config
    |> Config.fetch(:authentication_channel)
    |> case do
      {:ok, auth_channel} when auth_channel in @auth_channels -> {:ok, auth_channel}
      {:ok, auth_channel} -> cerr(:unknown_authentication_channel, details: auth_channel)
      error -> error
    end
  end

  defp enrich_config(config) do
    Keyword.merge(@default_config, config)
  end

  defp cerr(error, opts \\ []) when is_atom(error) do
    error_uri = Keyword.get(opts, :error_uri, nil)
    message = get_error_message(error, opts)

    {:error, CallbackError.exception(message: message, error: error, error_uri: error_uri)}
  end

  defp get_error_message(error, opts) do
    error
    |> error_to_message()
    |> maybe_inject_details(opts)
  end

  defp maybe_inject_details(message, opts) do
    details = Keyword.get(opts, :details)

    if Keyword.has_key?(opts, :details),
      do: "#{message}: #{inspect(details)}",
      else: message
  end

  defp error_to_message(error) do
    [
      init_data_with_login_widget: "Init data provided for the login widget authentication",
      init_data_empty:
        "Empty init data string provided for the Web mini app authentication. The page opened not from Telegram?",
      no_init_data:
        "Web mini app authentication requires initial WebAppInitData.initData string as `:init_data` key in the callback params",
      missing_hash_key:
        "Missing hash key in the response params, cannot verify the authenticity of the response",
      missing_auth_date_key:
        "Missing auth_date key in the response params, cannot verify the response",
      authenticity_check_failed:
        "Data authenticity check failed: the provided hash does not match the data",
      auth_request_expired: "The authentication request has expired",
      auth_date_in_future: "Auth date is in the future, possible tampering or clock skew detected"
    ]
    |> Keyword.get(error, :none)
    |> case do
      :none -> stringify(error)
      message -> message
    end
  end

  defp stringify(atom) when is_atom(atom) do
    atom
    |> Atom.to_string()
    |> String.split("_")
    |> Enum.join(" ")
    |> String.capitalize()
  end
end
