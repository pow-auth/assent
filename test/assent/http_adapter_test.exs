defmodule Assent.HTTPAdapterTest do
  use Assent.TestCase
  doctest Assent.Strategy

  alias Assent.{HTTPAdapter, HTTPAdapter.HTTPResponse, InvalidResponseError}

  defmodule HTTPMock do
    @json_library (Code.ensure_loaded?(JSON) && JSON) || Jason

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
         body: @json_library.encode!(%{"a" => 1})
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
         body: @json_library.encode!(%{"a" => 1})
       }}
    end

    def request(:get, "invalid-json-body", nil, [], nil) do
      {:ok,
       %HTTPResponse{status: 200, headers: [{"content-type", "application/json"}], body: "%"}}
    end

    def request(:get, "json-no-headers", nil, [], nil) do
      {:ok, %HTTPResponse{status: 200, headers: [], body: @json_library.encode!(%{"a" => 1})}}
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
    assert HTTPAdapter.request(:get, "http-adapter", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [],
                body: nil,
                http_adapter: HTTPMock,
                request_url: "http-adapter"
              }}

    assert HTTPAdapter.request(:get, "http-adapter-with-opts", nil, [],
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

    assert HTTPAdapter.request(:get, "json-encoded-body", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/json"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "json-encoded-body"
              }}

    assert HTTPAdapter.request(:get, "json-encoded-body-already-decoded", nil, [],
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

    assert HTTPAdapter.request(:get, "json-encoded-body-text/javascript-header", nil, [],
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

    assert {:error, %InvalidResponseError{}} =
             HTTPAdapter.request(:get, "invalid-json-body", nil, [], http_adapter: HTTPMock)

    assert HTTPAdapter.request(:get, "json-no-headers", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [],
                body: @json_library.encode!(%{"a" => 1}),
                http_adapter: HTTPMock,
                request_url: "json-no-headers"
              }}

    assert HTTPAdapter.request(:get, "form-data-body", nil, [], http_adapter: HTTPMock) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/x-www-form-urlencoded"}],
                body: %{"a" => "1"},
                http_adapter: HTTPMock,
                request_url: "form-data-body"
              }}

    assert HTTPAdapter.request(:get, "form-data-body-already-decoded", nil, [],
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

    def encode!(_any), do: ""
  end

  @body %{"a" => "1", "b" => "2"}
  @headers [{"content-type", "application/json"}]
  @json_encoded_body @json_library.encode!(@body)
  @uri_encoded_body URI.encode_query(@body)

  test "decode_response/2" do
    assert {:ok, response} =
             HTTPAdapter.decode_response(
               %HTTPResponse{body: @json_encoded_body, headers: @headers},
               []
             )

    assert response.body == @body

    assert {:ok, response} =
             HTTPAdapter.decode_response(
               %HTTPResponse{
                 body: @json_encoded_body,
                 headers: [{"content-type", "application/json; charset=utf-8"}]
               },
               []
             )

    assert response.body == @body

    assert {:ok, response} =
             HTTPAdapter.decode_response(
               %HTTPResponse{
                 body: @json_encoded_body,
                 headers: [{"content-type", "text/javascript"}]
               },
               []
             )

    assert response.body == @body

    assert {:ok, response} =
             HTTPAdapter.decode_response(
               %HTTPResponse{
                 body: @uri_encoded_body,
                 headers: [{"content-type", "application/x-www-form-urlencoded"}]
               },
               []
             )

    assert response.body == @body

    assert {:ok, response} =
             HTTPAdapter.decode_response(%HTTPResponse{body: @body, headers: []}, [])

    assert response.body == @body

    assert {:error, %InvalidResponseError{} = error} =
             HTTPAdapter.decode_response(%HTTPResponse{body: "%", headers: @headers}, [])

    assert error.response.body == "%"
  end
end
