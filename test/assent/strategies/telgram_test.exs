defmodule Assent.Strategies.TelgramTest do
  use ExUnit.Case


  alias Assent.Strategies.Telegram

  # 1_000 years
  @max_auth_validity_sec 31_536_000_000

  @config_login [
    bot_token: "9957363869:yJUV5C4xrLSn9wA9HpF3r5vGfLm5cy3hWuH",
    authentication_channel: :login_widget,
    max_auth_validity_sec: @max_auth_validity_sec
  ]

  @config_mini_app [
    bot_token: "9957363869:yJUV5C4xrLSn9wA9HpF3r5vGfLm5cy3hWuH",
    authentication_channel: :web_mini_app,
    max_auth_validity_sec: @max_auth_validity_sec
  ]

  @login_widget_callback_params %{
    "auth_date" => "1718262224",
    "first_name" => "Paul",
    "last_name" => "Duroff",
    "hash" => "ec9a1333e072bcba901e3fb8b1a124fa9c30234309d03f4e30f0c8ba58f7a43c",
    "id" => "928474348",
    "photo_url" => "https://t.me/i/userpic/320/H43c-6BjdPSD-gFkKcLU22upkRkJ5EsZ6Jy-3EvZqR4.jpg",
    "username" => "duroff"
  }

  @login_widget_claims %{
    "sub" => 928_474_348,
    "name" => "Paul Duroff",
    "family_name" => "Duroff",
    "given_name" => "Paul",
    "preferred_username" => "duroff",
    "picture" => "https://t.me/i/userpic/320/H43c-6BjdPSD-gFkKcLU22upkRkJ5EsZ6Jy-3EvZqR4.jpg",
    "authenticated_at" => ~U[2024-06-13 07:03:44Z]
  }

  @login_widget_wrong_hash "ba7df7c892c36105172bc1e67ff4417c0f80f4b04d3defbef047cd5251f92972"

  @web_app_callback_request_params %{
    init_data:
      ~s(user=%7B%22id%22%3A928474348%2C%22first_name%22%3A%22Paul%22%2C%22last_name%22%3A%22Duroff%22%2C%22language_code%22%3A%22en%22%2C%22allows_write_to_pm%22%3A%22true%22%7D&chat_instance=-6755728357363932889&chat_type=sender&auth_date=1718266103&hash=ba7df7c892c36105172bc1e67ff4417c0f80f4b04d3defbef047cd5251f92972)
  }

  @web_app_claims %{
    "sub" => 928_474_348,
    "allows_write_to_pm" => "true",
    "family_name" => "Duroff",
    "given_name" => "Paul",
    "name" => "Paul Duroff",
    "locale" => "en",
    "authenticated_at" => ~U[2024-06-13 08:08:23Z]
  }

  @web_app_wrong_hash "ec9a1333e072bcba901e3fb8b1a124fa9c30234309d03f4e30f0c8ba58f7a43c"

  test "authorize_url/1" do
    {:error, "Telegram does not support direct authorization request, please check docs"} =
      Telegram.authorize_url(@config_login)

    {:error, "Telegram does not support direct authorization request, please check docs"} =
      Telegram.authorize_url(@config_mini_app)
  end

  describe "callback/2 should return" do
    test "user claims for the login widget" do
      assert {:ok, %{user: user}} =
               Telegram.callback(@config_login, @login_widget_callback_params)

      assert user == @login_widget_claims
    end

    test "user claims for the web mini app" do
      assert {:ok, %{user: user}} =
               Telegram.callback(@config_mini_app, @web_app_callback_request_params)

      assert user == @web_app_claims
    end

    test "error if max auth validity exceeded for the login widget" do
      max_auth_validity_sec = 60
      config = Keyword.put(@config_login, :max_auth_validity_sec, max_auth_validity_sec)

      assert {:error, error} =
               Telegram.callback(config, @login_widget_callback_params)

      assert error ==
               %Assent.CallbackError{
                 message: "The authentication request has expired",
                 error: :auth_request_expired
               }
    end

    test "error if max auth validity exceeded the web mini app" do
      max_auth_validity_sec = 60
      config = Keyword.put(@config_mini_app, :max_auth_validity_sec, max_auth_validity_sec)

      assert {:error, error} =
               Telegram.callback(config, @web_app_callback_request_params)

      assert error ==
               %Assent.CallbackError{
                 message: "The authentication request has expired",
                 error: :auth_request_expired
               }
    end

    test "error if hash is wrong for the login widget" do
      login_widget_callback_wrong_hash_params = %{
        @login_widget_callback_params
        | "hash" => @login_widget_wrong_hash
      }

      assert {:error, error} =
               Telegram.callback(@config_login, login_widget_callback_wrong_hash_params)

      assert error ==
               %Assent.CallbackError{
                 error: :authenticity_check_failed,
                 message:
                   "Data authenticity check failed: the provided hash does not match the data"
               }
    end

    test "error if hash is wrong for the web mini app" do
      init_data = @web_app_callback_request_params.init_data

      init_data_wrong_hash =
        String.replace(init_data, ~r/hash=.*$/, "hash=#{@web_app_wrong_hash}")

      web_app_wrong_request_params = %{
        @web_app_callback_request_params
        | init_data: init_data_wrong_hash
      }

      assert {:error, error} = Telegram.callback(@config_mini_app, web_app_wrong_request_params)

      assert error ==
               %Assent.CallbackError{
                 error: :authenticity_check_failed,
                 message:
                   "Data authenticity check failed: the provided hash does not match the data"
               }
    end

    test "error if initData string is empty for the web mini app" do
      web_app_wrong_request_params = %{@web_app_callback_request_params | init_data: ""}

      assert {:error, error} = Telegram.callback(@config_mini_app, web_app_wrong_request_params)

      assert error ==
               %Assent.CallbackError{
                 error: :init_data_empty,
                 message:
                   "Empty init data string provided for the Web mini app authentication. The page opened not from Telegram?"
               }
    end
  end
end
