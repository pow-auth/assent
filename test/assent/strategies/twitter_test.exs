defmodule Assent.Strategy.TwitterTest do
  use Assent.Test.OAuthTestCase

  alias Assent.Strategy.Twitter

  @user_response %{
    email: nil,
    contributors_enabled: true,
    created_at: "Sat May 09 17:58:22 +0000 2009",
    default_profile: false,
    default_profile_image: false,
    description: "I taught your phone that thing you like.  The Mobile Partner Engineer @Twitter. ",
    favourites_count: 588,
    follow_request_sent: nil,
    followers_count: 10_625,
    following: nil,
    friends_count: 1181,
    geo_enabled: true,
    id: 38_895_958,
    id_str: "38895958",
    is_translator: false,
    lang: "en",
    listed_count: 190,
    location: "San Francisco",
    name: "Sean Cook",
    notifications: nil,
    profile_background_color: "1A1B1F",
    profile_background_image_url: "http://a0.twimg.com/profile_background_images/495742332/purty_wood.png",
    profile_background_image_url_https: "https://si0.twimg.com/profile_background_images/495742332/purty_wood.png",
    profile_background_tile: true,
    profile_image_url: "http://a0.twimg.com/profile_images/1751506047/dead_sexy_normal.JPG",
    profile_image_url_https: "https://si0.twimg.com/profile_images/1751506047/dead_sexy_normal.JPG",
    profile_link_color: "2FC2EF",
    profile_sidebar_border_color: "181A1E",
    profile_sidebar_fill_color: "252429",
    profile_text_color: "666666",
    profile_use_background_image: true,
    protected: false,
    screen_name: "theSeanCook",
    show_all_inline_media: true,
    status: %{
      contributors: nil,
      coordinates: %{
        coordinates: [
          -122.45037293,
          37.76484123
        ],
        type: "Point"
      },
      created_at: "Tue Aug 28 05:44:24 +0000 2012",
      favorited: false,
      geo: %{
        coordinates: [
          37.76484123,
          -122.45037293
        ],
        type: "Point"
      },
      id: 240_323_931_419_062_272,
      id_str: "240323931419062272",
      in_reply_to_screen_name: "messl",
      in_reply_to_status_id: 240_316_959_173_009_410,
      in_reply_to_status_id_str: "240316959173009410",
      in_reply_to_user_id: 18_707_866,
      in_reply_to_user_id_str: "18707866",
      place: %{
        attributes: %{},
        bounding_box: %{
          coordinates: [
            [
              [-122.45778216, 37.75932999],
              [-122.44248216, 37.75932999],
              [-122.44248216, 37.76752899],
              [-122.45778216, 37.76752899]
            ]
          ],
          type: "Polygon"
        },
        country: "United States",
        country_code: "US",
        full_name: "Ashbury Heights, San Francisco",
        id: "866269c983527d5a",
        name: "Ashbury Heights",
        place_type: "neighborhood",
        url: "http://api.twitter.com/1/geo/id/866269c983527d5a.json"
      },
      retweet_count: 0,
      retweeted: false,
      source: "Twitter for  iPhone",
      text: "@messl congrats! So happy for all 3 of you.",
      truncated: false
    },
    statuses_count: 2609,
    time_zone: "Pacific Time (US & Canada)",
    url: nil,
    utc_offset: -28_800,
    verified: false
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
    assert user == %{
      "description" =>
        "I taught your phone that thing you like.  The Mobile Partner Engineer @Twitter. ",
      "image" => "https://si0.twimg.com/profile_images/1751506047/dead_sexy_normal.JPG",
      "location" => "San Francisco",
      "name" => "Sean Cook",
      "nickname" => "theSeanCook",
      "uid" => 38_895_958,
      "urls" => %{"Twitter" => "https://twitter.com/theSeanCook"}
    }
  end
end
