defmodule Assent.Strategy.TwitterTest do
  use Assent.Test.OAuthTestCase

  alias Assent.{CallbackError, Strategy.Twitter}

  # From https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials
  @user_response %{
    "id" => 2_244_994_945,
    "id_str" => "2244994945",
    "name" => "Twitter Dev",
    "screen_name" => "TwitterDev",
    "location" => "Internet",
    "description" =>
      "Your official source for Twitter Platform news, updates & events. Need technical help? Visit https://t.co/mGHnxZU8c1 ⌨️ #TapIntoTwitter",
    "url" => "https://t.co/FGl7VOULyL",
    "entities" => %{
      "url" => %{
        "urls" => [
          %{
            "url" => "https://t.co/FGl7VOULyL",
            "expanded_url" => "https://developer.twitter.com/",
            "display_url" => "developer.twitter.com",
            "indices" => [
              0,
              23
            ]
          }
        ]
      },
      "description" => %{
        "urls" => [
          %{
            "url" => "https://t.co/mGHnxZU8c1",
            "expanded_url" => "https://twittercommunity.com/",
            "display_url" => "twittercommunity.com",
            "indices" => [
              93,
              116
            ]
          }
        ]
      }
    },
    "protected" => false,
    "followers_count" => 502_017,
    "friends_count" => 1_472,
    "listed_count" => 1_513,
    "created_at" => "Sat Dec 14 04:35:55 +0000 2013",
    "favourites_count" => 2_203,
    "utc_offset" => nil,
    "time_zone" => nil,
    "geo_enabled" => true,
    "verified" => true,
    "statuses_count" => 3_393,
    "lang" => "en",
    "status" => %{
      "created_at" => "Tue May 14 17:54:29 +0000 2019",
      "id" => 1_128_357_932_238_823_424,
      "id_str" => "1128357932238823424",
      "text" =>
        "We’ll release the first Labs endpoints to all eligible developers in the coming weeks. If you want to participate,… https://t.co/8q8sj87D5a",
      "truncated" => true,
      "entities" => %{
        "hashtags" => [],
        "symbols" => [],
        "user_mentions" => [],
        "urls" => [
          %{
            "url" => "https://t.co/8q8sj87D5a",
            "expanded_url" => "https://twitter.com/i/web/status/1128357932238823424",
            "display_url" => "twitter.com/i/web/status/1…",
            "indices" => [
              116,
              139
            ]
          }
        ]
      },
      "source" => "<a href=\"https://mobile.twitter.com\" rel=\"nofollow\">Twitter Web App</a>",
      "in_reply_to_status_id" => 1_128_357_931_026_501_633,
      "in_reply_to_status_id_str" => "1128357931026501633",
      "in_reply_to_user_id" => 2_244_994_945,
      "in_reply_to_user_id_str" => "2244994945",
      "in_reply_to_screen_name" => "TwitterDev",
      "geo" => nil,
      "coordinates" => nil,
      "place" => nil,
      "contributors" => nil,
      "is_quote_status" => false,
      "retweet_count" => 12,
      "favorite_count" => 37,
      "favorited" => false,
      "retweeted" => false,
      "possibly_sensitive" => false,
      "lang" => "en"
    },
    "contributors_enabled" => false,
    "is_translator" => false,
    "is_translation_enabled" => nil,
    "profile_background_color" => "null",
    "profile_background_image_url" => "null",
    "profile_background_image_url_https" => "null",
    "profile_background_tile" => nil,
    "profile_image_url" => "null",
    "profile_image_url_https" =>
      "https://pbs.twimg.com/profile_images/880136122604507136/xHrnqf1T_normal.jpg",
    "profile_banner_url" => "https://pbs.twimg.com/profile_banners/2244994945/1498675817",
    "profile_link_color" => "null",
    "profile_sidebar_border_color" => "null",
    "profile_sidebar_fill_color" => "null",
    "profile_text_color" => "null",
    "profile_use_background_image" => nil,
    "has_extended_profile" => nil,
    "default_profile" => false,
    "default_profile_image" => false,
    "following" => false,
    "follow_request_sent" => false,
    "notifications" => false,
    "translator_type" => "regular"
  }
  @user %{
    "name" => "Twitter Dev",
    "email_verified" => true,
    "picture" => "https://pbs.twimg.com/profile_images/880136122604507136/xHrnqf1T_normal.jpg",
    "preferred_username" => "TwitterDev",
    "profile" => "https://twitter.com/TwitterDev",
    "sub" => 2_244_994_945,
    "website" => "https://t.co/FGl7VOULyL"
  }

  setup %{config: config, callback_params: callback_params} do
    config = Keyword.merge(config, consumer_key: "cChZNFj6T5R0TigYB9yd1w")

    callback_params =
      Map.merge(callback_params, %{
        "oauth_token" => "NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0",
        "oauth_verifier" => "uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY"
      })

    {:ok, config: config, callback_params: callback_params}
  end

  test "authorize_url/2", %{config: config} do
    expect_oauth_request_token_request(
      uri: "/oauth/request_token",
      params: %{
        oauth_token: "NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0",
        oauth_token_secret: "veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI",
        oauth_callback_confirmed: true
      }
    )

    assert {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}} =
             Twitter.authorize_url(config)

    assert url ==
             TestServer.url(
               "/oauth/authenticate?oauth_token=NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0"
             )

    refute is_nil(oauth_token_secret)
  end

  test "callback/2", %{config: config, callback_params: params} do
    expect_oauth_access_token_request(
      [
        uri: "/oauth/access_token",
        params: %{
          oauth_token: "7588892-kagSNqWge8gB1WwE3plnFsJHAZVfxWD7Vb57p0b4",
          oauth_token_secret: "PbKfYqSryyeKDWz4ebtY3o5ogNLG11WJuZBc9fQrQo"
        }
      ],
      fn _conn, oauth_params ->
        assert oauth_params["oauth_consumer_key"] == "cChZNFj6T5R0TigYB9yd1w"
        assert oauth_params["oauth_token"] == "NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0"
        assert oauth_params["oauth_verifier"] == "uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY"
      end
    )

    expect_oauth_user_request(@user_response,
      uri: "/1.1/account/verify_credentials.json",
      params: [include_entities: false, skip_status: true, include_email: true]
    )

    assert {:ok, %{user: user}} = Twitter.callback(config, params)
    assert user == @user
  end

  test "callback/2 when user denies", %{config: config, callback_params: params} do
    assert {:error, %CallbackError{} = error} =
             Twitter.callback(config, %{"denied" => params["oauth_token"]})

    assert error.message == "The user denied the authorization request"
    refute error.error
    refute error.error_uri
  end
end
