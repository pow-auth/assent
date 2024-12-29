defmodule Assent.Strategy.TelegramTest do
  use ExUnit.Case

  alias Assent.Strategy.Telegram

  @callback_params %{
    "first_name" => "Paul",
    "last_name" => "Duroff",
    "id" => "928474348",
    "photo_url" => "https://t.me/i/userpic/320/H43c-6BjdPSD-gFkKcLU22upkRkJ5EsZ6Jy-3EvZqR4.jpg",
    "username" => "duroff"
  }
  @user %{
    "sub" => 928_474_348,
    "family_name" => "Duroff",
    "given_name" => "Paul",
    "preferred_username" => "duroff",
    "picture" => "https://t.me/i/userpic/320/H43c-6BjdPSD-gFkKcLU22upkRkJ5EsZ6Jy-3EvZqR4.jpg"
  }

  defp generate_hash(params, secret) do
    data =
      params
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)
      |> Enum.sort()
      |> Enum.join("\n")

    :hmac
    |> :crypto.mac(:sha256, secret, data)
    |> Base.encode16(case: :lower)
  end

  setup context do
    default_config =
      [
        bot_token: "9999999999:yJUV5C4xrLSn9wA9HpF3r5vGfLm5cy3hWuH",
        origin: "http://localhost:4000/login",
        return_to: "http://localhost:4000/auth/callback"
      ]

    auth_date = DateTime.utc_now() |> DateTime.to_unix() |> Integer.to_string()
    default_params = Map.put(@callback_params, "auth_date", auth_date)

    {config, params} =
      case Map.get(context, :authorization_channel, :login_widget) do
        :login_widget ->
          hash = generate_hash(default_params, :crypto.hash(:sha256, default_config[:bot_token]))

          {default_config, Map.put(default_params, "hash", hash)}

        :web_mini_app ->
          hash =
            generate_hash(
              default_params,
              :crypto.mac(:hmac, :sha256, "WebAppData", default_config[:bot_token])
            )

          init_data = URI.encode_query(Map.put(default_params, "hash", hash))
          config = Keyword.put(default_config, :authorization_channel, :web_mini_app)

          {config, %{"init_data" => init_data}}
      end

    {:ok, config: config, callback_params: params}
  end

  describe "authorize_url/1" do
    test "with missing `:bot_token` config", %{config: config} do
      config = Keyword.delete(config, :bot_token)

      assert {:error, %Assent.MissingConfigError{} = error} = Telegram.authorize_url(config)
      assert error.key == :bot_token
    end

    test "with missing `:origin` config", %{config: config} do
      config = Keyword.delete(config, :origin)

      assert {:error, %Assent.MissingConfigError{} = error} = Telegram.authorize_url(config)
      assert error.key == :origin
    end

    test "with missing `:return_to` config", %{config: config} do
      config = Keyword.delete(config, :return_to)

      assert {:error, %Assent.MissingConfigError{} = error} = Telegram.authorize_url(config)
      assert error.key == :return_to
    end

    test "returns", %{config: config} do
      assert {:ok, %{url: url}} = Telegram.authorize_url(config)

      assert URI.decode_query(URI.parse(url).query) == %{
               "bot_id" => "9999999999",
               "origin" => "http://localhost:4000/login",
               "return_to" => "http://localhost:4000/auth/callback",
               "request_access" => "read",
               "embed" => "0"
             }
    end
  end

  describe "callback/2" do
    test "with invalid `:authorization_channel` config", %{
      config: config,
      callback_params: callback_params
    } do
      config = Keyword.put(config, :authorization_channel, :invalid)

      assert {:error, %Assent.CallbackError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.message == "Invalid `:authorization_channel` value: :invalid"
    end

    test "with missing hash param", %{config: config, callback_params: callback_params} do
      callback_params = Map.delete(callback_params, "hash")

      assert {:error, %Assent.MissingParamError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.key == "hash"
    end

    @tag authorization_channel: :web_mini_app
    test "with web mini app with missing init_data param", %{
      config: config,
      callback_params: callback_params
    } do
      callback_params = Map.delete(callback_params, "init_data")

      assert {:error, %Assent.MissingParamError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.key == "init_data"
    end

    test "with missing auth_date param", %{config: config, callback_params: callback_params} do
      callback_params = Map.delete(callback_params, "auth_date")

      assert {:error, %Assent.MissingParamError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.key == "auth_date"
    end

    test "with expired auth_date param", %{config: config, callback_params: callback_params} do
      expired_auth_date =
        DateTime.utc_now() |> DateTime.to_unix() |> Kernel.-(61) |> Integer.to_string()

      callback_params = Map.put(callback_params, "auth_date", expired_auth_date)

      assert {:error, %Assent.CallbackError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.message == "Authorization request has expired"
    end

    test "with missing bot_token config", %{config: config, callback_params: callback_params} do
      config = Keyword.delete(config, :bot_token)

      assert {:error, %Assent.MissingConfigError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.key == :bot_token
    end

    test "with invalid hash", %{config: config, callback_params: callback_params} do
      config = Keyword.put(config, :bot_token, "other-token")

      assert {:error, %Assent.CallbackError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.message == "Authorization request has an invalid hash"
    end

    @tag authorization_channel: :web_mini_app
    test "with web mini app with invalid hash", %{
      config: config,
      callback_params: callback_params
    } do
      config = Keyword.put(config, :bot_token, "other-token")

      assert {:error, %Assent.CallbackError{} = error} =
               Telegram.callback(config, callback_params)

      assert error.message == "Authorization request has an invalid hash"
    end

    test "returns user", %{config: config, callback_params: callback_params} do
      assert {:ok, %{user: user}} = Telegram.callback(config, callback_params)
      assert user == @user
    end

    @tag authorization_channel: :web_mini_app
    test "with web mini app", %{config: config, callback_params: callback_params} do
      assert {:ok, %{user: user}} = Telegram.callback(config, callback_params)
      assert user == @user
    end
  end
end
