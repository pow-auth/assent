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

  test "normalize_userinfo/2" do
    user = %{"email" => "foo@example.com", "name" => nil, "nickname" => "foo"}
    extra = %{"a" => "1"}
    expected = %{"email" => "foo@example.com", "nickname" => "foo", "a" => "1"}

    assert Strategy.normalize_userinfo(user, extra) == {:ok, expected}
  end

  test "prune/1" do
    map = %{a: :ok, b: nil, c: "", d: %{a: :ok, b: nil}}
    expected = %{a: :ok, c: "", d: %{a: :ok}}

    assert Strategy.prune(map) == expected
  end
end
