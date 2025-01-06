defmodule Assent.StrategyTest do
  use Assent.TestCase
  doctest Assent.Strategy

  alias Assent.Strategy

  defmodule HTTPMock do
    def request(:get, _, _, _, _), do: {:error, __MODULE__}
  end

  defmodule JSONMock do
    def decode(_string), do: {:ok, :decoded}
  end

  defmodule JWTMock do
    @moduledoc false

    def sign(_claims, _alg, _secret, opts), do: {:error, opts}

    def verify(_binary, _secret, opts), do: {:error, opts}
  end

  test "http_request/5" do
    config = [http_adapter: HTTPMock, json_library: JSONMock]

    assert {:error, error} = Strategy.http_request(:get, "/path", nil, [], config)
    assert error.reason == HTTPMock
  end

  test "sign_jwt/4" do
    config = [json_library: JSONMock, jwt_adapter: JWTMock, private_key: "myprivatekey.pem", a: 1]

    assert {:error, opts} = Strategy.sign_jwt(%{"claim" => "a"}, "alg", "secret", config)
    assert opts == [json_library: JSONMock, jwt_adapter: JWTMock]
  end

  test "verify_jwt/4" do
    config = [json_library: JSONMock, jwt_adapter: JWTMock, private_key: "myprivatekey.pem", a: 1]

    assert {:error, opts} = Strategy.verify_jwt("token", "secret", config)
    assert opts == [json_library: JSONMock, jwt_adapter: JWTMock]
  end

  test "decode_json/2" do
    assert Strategy.decode_json("{\"a\": 1}", []) == {:ok, %{"a" => 1}}
    assert Strategy.decode_json("{\"a\": 1}", json_library: JSONMock) == {:ok, :decoded}
  end

  test "to_url/3" do
    assert Strategy.to_url("http://example.com", "/path") == "http://example.com/path"
    assert Strategy.to_url("http://example.com/", "/path") == "http://example.com/path"

    assert Strategy.to_url("http://example.com/path", "/other-path") ==
             "http://example.com/path/other-path"

    assert Strategy.to_url("http://example.com/path/", "/other-path") ==
             "http://example.com/path/other-path"

    assert Strategy.to_url("http://example.com/path", "http://example.org/other-path") ==
             "http://example.org/other-path"

    assert Strategy.to_url("http://example.com", "/path", a: 1, b: [c: 2, d: [e: 3]], f: [4, 5]) ==
             "http://example.com/path?a=1&b[c]=2&b[d][e]=3&f[]=4&f[]=5"
  end

  describe "normalize_userinfo/2" do
    @valid_user %{
      "sub" => "123",
      "email" => "foo@example.com",
      "email_verified" => true,
      "address" => %{
        "formatted" => "456"
      },
      "updated_at" => 1_516_239_022
    }

    @invalid_user %{
      "sub" => true,
      "address" => %{
        "formatted" => true
      }
    }

    @expected_user %{
      "sub" => "123",
      "email" => "foo@example.com",
      "email_verified" => true,
      "address" => %{
        "formatted" => "456"
      },
      "updated_at" => 1_516_239_022
    }

    test "with incorrect claim type" do
      assert {:error, %Assent.CastClaimsError{} = error} =
               Strategy.normalize_userinfo(@invalid_user, %{})

      assert Exception.message(error) == """
             The following claims couldn't be cast:

             - "address" -> "formatted" to :binary
             - "sub" to :binary
             """
    end

    test "with atom value claim" do
      user = %{"sub" => :invalid}

      assert {:error, %Assent.CastClaimsError{} = error} = Strategy.normalize_userinfo(user, %{})
      assert error.invalid_types == %{"sub" => :binary}
    end

    test "with binary type claim with integer value" do
      user = %{"sub" => 123}

      assert {:ok, %{"sub" => "123"}} = Strategy.normalize_userinfo(user, %{})
    end

    test "with integer type claim with invalid binary value" do
      user = %{"updated_at" => "123a1"}

      assert {:error, %Assent.CastClaimsError{} = error} = Strategy.normalize_userinfo(user, %{})
      assert error.invalid_types == %{"updated_at" => :integer}
    end

    test "with integer type claim with valid binary value" do
      user = %{"updated_at" => "123"}

      assert {:ok, %{"updated_at" => 123}} = Strategy.normalize_userinfo(user, %{})
    end

    test "with boolean type claim with string binary value" do
      user = %{"email_verified" => "true"}

      assert {:ok, %{"email_verified" => true}} = Strategy.normalize_userinfo(user, %{})

      user = %{"email_verified" => "false"}

      assert {:ok, %{"email_verified" => false}} = Strategy.normalize_userinfo(user, %{})
    end

    test "casts" do
      assert Strategy.normalize_userinfo(@valid_user) == {:ok, @expected_user}
    end

    test "with unknown claims" do
      user =
        @valid_user
        |> Map.put("foo", "bar")
        |> Map.put("address", Map.put(@valid_user["address"], "foo", "bar"))

      assert Strategy.normalize_userinfo(user) == {:ok, @expected_user}
    end

    test "with extra" do
      extra =
        %{
          "a" => 1,
          "b" => nil,
          "sub" => "other-sub",
          "address" => %{
            "formatted" => "other-foramtted",
            "a" => nil,
            "b" => 2
          }
        }

      expected_user =
        @expected_user
        |> Map.put("a", 1)
        |> Map.put("address", Map.put(@expected_user["address"], "b", 2))

      assert Strategy.normalize_userinfo(@valid_user, extra) == {:ok, expected_user}
    end
  end
end
