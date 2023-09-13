defmodule Assent.Strategy.StravaTest do
  use Assent.Test.OAuth2TestCase

  alias Assent.Strategy.Strava

  # Sample from https://developers.strava.com/docs/reference/#api-Athletes-getLoggedInAthlete
  @user_response %{
    "id" => 1_234_567_890_987_654_321,
    "username" => "marianne_t",
    "resource_state" => 3,
    "firstname" => "Marianne",
    "lastname" => "Teutenberg",
    "city" => "San Francisco",
    "state" => "CA",
    "country" => "US",
    "sex" => "F",
    "premium" => true,
    "created_at" => "2017-11-14T02:30:05Z",
    "updated_at" => "2018-02-06T19:32:20Z",
    "badge_type_id" => 4,
    "profile_medium" =>
      "https://xxxxxx.cloudfront.net/pictures/athletes/123456789/123456789/2/medium.jpg",
    "profile" => "https://xxxxx.cloudfront.net/pictures/athletes/123456789/123456789/2/large.jpg",
    "friend" => nil,
    "follower" => nil,
    "follower_count" => 5,
    "friend_count" => 5,
    "mutual_friend_count" => 0,
    "athlete_type" => 1,
    "date_preference" => "%m/%d/%Y",
    "measurement_preference" => "feet",
    "clubs" => [],
    "ftp" => nil,
    "weight" => 0,
    "bikes" => [
      %{
        "id" => "b12345678987655",
        "primary" => true,
        "name" => "EMC",
        "resource_state" => 2,
        "distance" => 0
      }
    ],
    "shoes" => [
      %{
        "id" => "g12345678987655",
        "primary" => true,
        "name" => "adidas",
        "resource_state" => 2,
        "distance" => 4904
      }
    ]
  }

  @user %{
    "sub" => 1_234_567_890_987_654_321,
    "given_name" => "Marianne",
    "family_name" => "Teutenberg",
    "preferred_username" => "marianne_t",
    "picture" => "https://xxxxx.cloudfront.net/pictures/athletes/123456789/123456789/2/large.jpg"
  }

  test "authorize_url/2", %{config: config} do
    assert {:ok, %{url: url}} = Strava.authorize_url(config)
    assert url =~ "https://www.strava.com/oauth/authorize?client_id="
  end

  describe "callback/2" do
    setup %{config: config} do
      config = Keyword.put(config, :token_url, TestServer.url("/login/oauth/access_token"))

      {:ok, config: config}
    end

    test "normalizes data", %{config: config, callback_params: params} do
      expect_oauth2_access_token_request([uri: "/login/oauth/access_token"], fn _conn, params ->
        assert params["client_secret"] == config[:client_secret]
      end)

      expect_oauth2_user_request(@user_response, uri: "/athlete")

      assert {:ok, %{user: user}} = Strava.callback(config, params)
      assert user == @user
    end
  end
end
