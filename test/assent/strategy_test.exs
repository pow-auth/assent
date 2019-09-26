defmodule Assent.StrategyTest do
  use ExUnit.Case
  doctest Assent.Strategy

  alias Assent.Strategy

  test "prune/1" do
    map      = %{a: :ok, b: nil, c: "", d: %{a: :ok, b: nil}}
    expected = %{a: :ok, c: "", d: %{a: :ok}}

    assert Strategy.prune(map) == expected
  end

  test "decode_response/1" do
    expected = %{"a" => "1", "b" => "2"}

    headers = [{"content-type", "application/json"}]
    body = Jason.encode!(expected)
    assert Strategy.decode_response({nil, %{body: body, headers: headers}}, []) == {nil, %{body: expected, headers: headers}}

    headers = [{"content-type", "application/json; charset=utf-8"}]
    assert Strategy.decode_response({nil, %{body: body, headers: headers}}, []) == {nil, %{body: expected, headers: headers}}

    headers = [{"content-type", "text/javascript"}]
    assert Strategy.decode_response({nil, %{body: body, headers: headers}}, []) == {nil, %{body: expected, headers: headers}}

    headers = [{"content-type", "application/x-www-form-urlencoded"}]
    body = URI.encode_query(expected)
    assert Strategy.decode_response({nil, %{body: body, headers: headers}}, []) == {nil, %{body: expected, headers: headers}}

    headers = [{"content-type", "application/x-www-form-urlencoded; charset=utf-8"}]
    assert Strategy.decode_response({nil, %{body: body, headers: headers}}, []) == {nil, %{body: expected, headers: headers}}
  end

  defmodule JSONMock do
    def decode(_string), do: {:ok, :decoded}
  end

  test "decode_json/2" do
    assert Strategy.decode_json("{\"a\": 1}", []) == {:ok, %{"a" => 1}}
    assert Strategy.decode_json("{\"a\": 1}", json_library: JSONMock) == {:ok, :decoded}
  end

  defmodule HTTPMock do
    def request(_method, _url, _body, _headers, nil), do: {:ok, %{status: 200}}
    def request(_method, _url, _body, _headers, opts), do: {:ok, %{status: 200, opts: opts}}
  end

  test "request/5" do
    assert Strategy.request(:get, "https://localhost:4000/", nil, [], http_adapter: HTTPMock) == {:ok, %{status: 200}}
    assert Strategy.request(:get, "https://localhost:4000/", nil, [], http_adapter: {HTTPMock, a: 1}) == {:ok, %{status: 200, opts: [a: 1]}}
  end

  defmodule CustomJSONLibrary do
    @doc false
    def decode(_binary), do: {:ok, :decoded}
  end

  defmodule CustomJWTAdapter do
    @doc false
    def decode(_binary, _opts), do: :decoded
  end

  test "decode_jwt/2" do
    assert {:ok, %Assent.JWTAdapter.JWT{} = jwt} = Strategy.decode_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8", [])
    assert jwt.payload == %{"iat" => 1_516_239_022, "name" => "John Doe", "sub" => "1234567890"}
    assert jwt.header

    assert Strategy.decode_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8", [jwt_adapter: CustomJWTAdapter]) == :decoded

    assert {:ok, %Assent.JWTAdapter.JWT{} = jwt} = Strategy.decode_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8", [json_library: CustomJSONLibrary])
    assert jwt.payload == :decoded
  end
end
