defmodule Assent.StrategyTest do
  use ExUnit.Case
  doctest Assent.Strategy

  alias Assent.{HTTPAdapter.HTTPResponse, Strategy}

  test "decode_response/2" do
    expected = %{"a" => "1", "b" => "2"}

    headers = [{"content-type", "application/json"}]
    body = Jason.encode!(expected)

    assert Strategy.decode_response({:ok, %{body: body, headers: headers}}, []) ==
             {:ok, %{body: expected, headers: headers}}

    assert Strategy.decode_response({:error, %{body: body, headers: headers}}, []) ==
             {:error, %{body: expected, headers: headers}}

    headers = [{"content-type", "application/json; charset=utf-8"}]

    assert Strategy.decode_response({:ok, %{body: body, headers: headers}}, []) ==
             {:ok, %{body: expected, headers: headers}}

    headers = [{"content-type", "text/javascript"}]

    assert Strategy.decode_response({:ok, %{body: body, headers: headers}}, []) ==
             {:ok, %{body: expected, headers: headers}}

    headers = [{"content-type", "application/x-www-form-urlencoded"}]
    body = URI.encode_query(expected)

    assert Strategy.decode_response({:ok, %{body: body, headers: headers}}, []) ==
             {:ok, %{body: expected, headers: headers}}

    headers = [{"content-type", "application/x-www-form-urlencoded; charset=utf-8"}]

    assert Strategy.decode_response({:ok, %{body: body, headers: headers}}, []) ==
             {:ok, %{body: expected, headers: headers}}

    assert Strategy.decode_response({:error, "error reason"}, []) == {:error, "error reason"}
  end

  defmodule JSONMock do
    def decode(_string), do: {:ok, :decoded}
  end

  test "decode_json/2" do
    assert Strategy.decode_json("{\"a\": 1}", []) == {:ok, %{"a" => 1}}
    assert Strategy.decode_json("{\"a\": 1}", json_library: JSONMock) == {:ok, :decoded}
  end

  defmodule HTTPMock do
    def request(:get, "http-adapter", nil, [], nil) do
      {:ok, %HTTPResponse{status: 200, headers: [], body: nil}}
    end

    def request(:get, "http-adapter-with-opts", nil, [], opts) do
      {:ok, %HTTPResponse{status: 200, headers: [], body: opts}}
    end

    def request(:get, "json-encoded-body", nil, [], nil) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/json"}],
         body: Jason.encode!(%{"a" => 1})
       }}
    end

    def request(:get, "json-encoded-body-already-decoded", nil, [], nil) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/json"}],
         body: %{"a" => 1}
       }}
    end

    def request(:get, "json-encoded-body-text/javascript-header", nil, [], nil) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "text/javascript"}],
         body: Jason.encode!(%{"a" => 1})
       }}
    end

    def request(:get, "invalid-json-body", nil, [], nil) do
      {:ok,
       %HTTPResponse{status: 200, headers: [{"content-type", "application/json"}], body: "%"}}
    end

    def request(:get, "json-no-headers", nil, [], nil) do
      {:ok, %HTTPResponse{status: 200, headers: [], body: Jason.encode!(%{"a" => 1})}}
    end

    def request(:get, "form-data-body", nil, [], nil) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/x-www-form-urlencoded"}],
         body: URI.encode_query(%{"a" => 1})
       }}
    end

    def request(:get, "form-data-body-already-decoded", nil, [], nil) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/x-www-form-urlencoded"}],
         body: %{"a" => 1}
       }}
    end
  end

  test "request/5" do
    assert Strategy.request(:get, "http-adapter", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [],
                body: nil,
                http_adapter: HTTPMock,
                request_url: "http-adapter"
              }}

    assert Strategy.request(:get, "http-adapter-with-opts", nil, [],
             http_adapter: {HTTPMock, a: 1}
           ) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [],
                body: [a: 1],
                http_adapter: HTTPMock,
                request_url: "http-adapter-with-opts"
              }}

    assert Strategy.request(:get, "json-encoded-body", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/json"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "json-encoded-body"
              }}

    assert Strategy.request(:get, "json-encoded-body-already-decoded", nil, [],
             http_adapter: HTTPMock
           ) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/json"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "json-encoded-body-already-decoded"
              }}

    assert Strategy.request(:get, "json-encoded-body-text/javascript-header", nil, [],
             http_adapter: HTTPMock
           ) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "text/javascript"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "json-encoded-body-text/javascript-header"
              }}

    assert {:error, %Jason.DecodeError{}} =
             Strategy.request(:get, "invalid-json-body", nil, [], http_adapter: HTTPMock)

    assert Strategy.request(:get, "json-no-headers", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [],
                body: Jason.encode!(%{"a" => 1}),
                http_adapter: HTTPMock,
                request_url: "json-no-headers"
              }}

    assert Strategy.request(:get, "form-data-body", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/x-www-form-urlencoded"}],
                body: %{"a" => "1"},
                http_adapter: HTTPMock,
                request_url: "form-data-body"
              }}

    assert Strategy.request(:get, "form-data-body-already-decoded", nil, [],
             http_adapter: HTTPMock
           ) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/x-www-form-urlencoded"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "form-data-body-already-decoded"
              }}
  end

  defmodule CustomJWTAdapter do
    @moduledoc false

    def sign(_claims, _alg, _secret, _opts), do: :signed

    def verify(_binary, _secret, _opts), do: :verified
  end

  defmodule CustomJSONLibrary do
    @moduledoc false

    def decode(_binary), do: {:ok, %{"alg" => "none", "custom_json" => true}}

    def encode(_binary), do: {:ok, ""}
  end

  @claims %{"iat" => 1_516_239_022, "name" => "John Doe", "sub" => "1234567890"}
  @alg "HS256"
  @secret "your-256-bit-secret"
  @token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8"

  @empty_encoding Base.url_encode64("", padding: false)

  test "sign_jwt/2" do
    assert Strategy.sign_jwt(@claims, @alg, @secret, []) == {:ok, @token}

    assert Strategy.sign_jwt(@token, @alg, @secret, jwt_adapter: CustomJWTAdapter) == :signed

    assert {:ok, @empty_encoding <> "." <> _rest} =
             Strategy.sign_jwt(@token, @alg, @secret, json_library: CustomJSONLibrary)
  end

  test "verify_jwt/2" do
    assert {:ok, jwt} = Strategy.verify_jwt(@token, @secret, [])
    assert jwt.verified?
    assert Strategy.verify_jwt(@token, @secret, jwt_adapter: CustomJWTAdapter) == :verified

    assert {:ok, %{header: %{"custom_json" => true}}} =
             Strategy.verify_jwt(@token, @secret, json_library: CustomJSONLibrary)
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
