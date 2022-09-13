defmodule Assent.Strategy.StripeTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Stripe

  # From https://stripe.com/docs/api/accounts/retrieve
  @user_response %{
    "id" => "acct_1032D82eZvKYlo2C",
    "object" => "account",
    "business_profile" => %{
      "mcc" => nil,
      "name" => "Stripe.com",
      "product_description" => nil,
      "support_address" => nil,
      "support_email" => nil,
      "support_phone" => nil,
      "support_url" => nil,
      "url" => nil
    },
    "business_type" => nil,
    "capabilities" => %{
      "card_payments" => "active",
      "transfers" => "active"
    },
    "charges_enabled" => false,
    "country" => "US",
    "created" => 1_385_798_567,
    "default_currency" => "usd",
    "details_submitted" => false,
    "email" => "site@stripe.com",
    "external_accounts" => %{
      "object" => "list",
      "data" => [],
      "has_more" => false,
      "url" => "/v1/accounts/acct_1032D82eZvKYlo2C/external_accounts"
    },
    "metadata" => %{},
    "payouts_enabled" => false,
    "requirements" => %{
      "current_deadline" => nil,
      "currently_due" => [
        "business_profile.product_description",
        "business_profile.support_phone",
        "business_profile.url",
        "external_account",
        "tos_acceptance.date",
        "tos_acceptance.ip"
      ],
      "disabled_reason" => "requirements.past_due",
      "errors" => [],
      "eventually_due" => [
        "business_profile.product_description",
        "business_profile.support_phone",
        "business_profile.url",
        "external_account",
        "tos_acceptance.date",
        "tos_acceptance.ip"
      ],
      "past_due" => [],
      "pending_verification" => []
    },
    "settings" => %{
      "bacs_debit_payments" => %{},
      "branding" => %{
        "icon" => nil,
        "logo" => nil,
        "primary_color" => nil,
        "secondary_color" => nil
      },
      "card_payments" => %{
        "decline_on" => %{
          "avs_failure" => true,
          "cvc_failure" => false
        },
        "statement_descriptor_prefix" => nil
      },
      "dashboard" => %{
        "display_name" => "Stripe.com",
        "timezone" => "US/Pacific"
      },
      "payments" => %{
        "statement_descriptor" => nil,
        "statement_descriptor_kana" => nil,
        "statement_descriptor_kanji" => nil
      },
      "payouts" => %{
        "debit_negative_balances" => true,
        "schedule" => %{
          "delay_days" => 7,
          "interval" => "daily"
        },
        "statement_descriptor" => nil
      }
    },
    "tos_acceptance" => %{
      "date" => nil,
      "ip" => nil,
      "user_agent" => nil
    },
    "type" => "custom"
  }

  @user  %{
    "email" => "site@stripe.com",
    "sub" => "acct_1032D82eZvKYlo2C"
  }

  setup %{config: config} do
    config = Keyword.put(config, :token_url, TestServer.url("/oauth/token"))

    {:ok, config: config}
  end

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Stripe.authorize_url(config)
    assert url =~ "/oauth/authorize?client_id="
  end

  test "callback/2", %{config: config, callback_params: params} do
    expect_oauth2_access_token_request([], fn _conn, params ->
      assert params["client_secret"] == config[:client_secret]
    end)
    expect_oauth2_user_request(@user_response, uri: "/v1/account")

    assert {:ok, %{user: user}} = Stripe.callback(config, params)
    assert user == @user
  end
end
