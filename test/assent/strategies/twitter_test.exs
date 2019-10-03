defmodule Assent.Strategy.TwitterTest do
  use Assent.Test.OAuthTestCase

  alias Assent.Strategy.Twitter

  # From ttps://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials
  @user_response %{
    "id" => 2_244_994_945,
    "id_str" => "2244994945",
    "name" => "Twitter Dev",
    "screen_name" => "TwitterDev",
    "location" => "Internet",
    "description" => "Your official source for Twitter Platform news, updates & events. Need technical help? Visit https://t.co/mGHnxZU8c1 ⌨️ #TapIntoTwitter",
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
      "text" => "We’ll release the first Labs endpoints to all eligible developers in the coming weeks. If you want to participate,… https://t.co/8q8sj87D5a",
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
    "profile_image_url_https" => "https://pbs.twimg.com/profile_images/880136122604507136/xHrnqf1T_normal.jpg",
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
    "picture" => "https://pbs.twimg.com/profile_images/880136122604507136/xHrnqf1T_normal.jpg",
    "preferred_username" => "TwitterDev",
    "profile" => "https://twitter.com/TwitterDev",
    "sub" => 2_244_994_945,
    "website" => "https://t.co/FGl7VOULyL"
  }

  test "authorize_url/2", %{config: config, bypass: bypass} do
    expect_oauth_request_token_request(bypass)

    assert {:ok, %{url: url, session_params: %{oauth_token_secret: oauth_token_secret}}} = Twitter.authorize_url(config)
    assert url == "http://localhost:#{bypass.port}/oauth/authenticate?oauth_token=request_token"
    refute is_nil(oauth_token_secret)
  end

  test "callback/2", %{config: config, callback_params: params, bypass: bypass} do
    expect_oauth_access_token_request(bypass)
    expect_oauth_user_request(bypass, @user_response, uri: "/1.1/account/verify_credentials.json")

    assert {:ok, %{user: user}} = Twitter.callback(config, params)
    assert user == @user
  end
end
