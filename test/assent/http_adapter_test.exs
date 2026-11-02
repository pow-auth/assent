defmodule Assent.HTTPAdapterTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter
  doctest Assent.HTTPAdapter.HTTPResponse

  alias Assent.{
    HTTPAdapter,
    HTTPAdapter.HTTPRequest,
    HTTPAdapter.HTTPResponse,
    InvalidResponseError
  }

  defmodule HTTPMock do
    def request(:get, "http-adapter", nil, [], []) do
      {:ok, %HTTPResponse{status: 200, headers: [], body: nil}}
    end

    def request(:get, "http-adapter-with-opts", nil, [], opts) do
      {:ok, %HTTPResponse{status: 200, headers: [], body: opts}}
    end

    def request(:get, "json-encoded-body", nil, [], _opts) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/json"}],
         body: JSON.encode!(%{"a" => 1})
       }}
    end

    def request(:get, "json-encoded-body-already-decoded", nil, [], _opts) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/json"}],
         body: %{"a" => 1}
       }}
    end

    def request(:get, "json-encoded-body-text/javascript-header", nil, [], _opts) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "text/javascript"}],
         body: JSON.encode!(%{"a" => 1})
       }}
    end

    def request(:get, "invalid-json-body", nil, [], _opts) do
      {:ok,
       %HTTPResponse{status: 200, headers: [{"content-type", "application/json"}], body: "%"}}
    end

    def request(:get, "json-no-headers", nil, [], _opts) do
      {:ok, %HTTPResponse{status: 200, headers: [], body: JSON.encode!(%{"a" => 1})}}
    end

    def request(:get, "uppercase-header-names", nil, [], _opts) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"Content-Type", "application/json"}],
         body: JSON.encode!(%{"a" => 1})
       }}
    end

    def request(:get, "form-data-body", nil, [], _opts) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/x-www-form-urlencoded"}],
         body: URI.encode_query(%{"a" => 1})
       }}
    end

    def request(:get, "form-data-body-already-decoded", nil, [], _opts) do
      {:ok,
       %HTTPResponse{
         status: 200,
         headers: [{"content-type", "application/x-www-form-urlencoded"}],
         body: %{"a" => 1}
       }}
    end
  end

  test "request/2" do
    request = %HTTPRequest{method: :get}
    opts = [http_adapter: HTTPMock]

    assert HTTPAdapter.request(%{request | url: "http-adapter"}, opts) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [],
                body: nil,
                http_adapter: HTTPMock,
                request_url: "http-adapter"
              }}

    assert HTTPAdapter.request(%{request | url: "http-adapter-with-opts"},
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

    assert HTTPAdapter.request(%{request | url: "json-encoded-body"}, opts) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/json"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "json-encoded-body"
              }}

    assert HTTPAdapter.request(%{request | url: "json-encoded-body-already-decoded"}, opts) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/json"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "json-encoded-body-already-decoded"
              }}

    assert HTTPAdapter.request(%{request | url: "json-encoded-body-text/javascript-header"}, opts) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "text/javascript"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "json-encoded-body-text/javascript-header"
              }}

    assert HTTPAdapter.request(%{request | url: "invalid-json-body"}, opts) ==
             {:error,
              %Assent.InvalidResponseError{
                response: %Assent.HTTPAdapter.HTTPResponse{
                  http_adapter: Assent.HTTPAdapterTest.HTTPMock,
                  request_url: "invalid-json-body",
                  status: 200,
                  headers: [{"content-type", "application/json"}],
                  body: "%"
                }
              }}

    assert HTTPAdapter.request(%{request | url: "json-no-headers"}, opts) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [],
                body: JSON.encode!(%{"a" => 1}),
                http_adapter: HTTPMock,
                request_url: "json-no-headers"
              }}

    assert HTTPAdapter.request(%{request | url: "uppercase-header-names"}, opts) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/json"}],
                body: %{"a" => 1},
                http_adapter: HTTPMock,
                request_url: "uppercase-header-names"
              }}

    assert HTTPAdapter.request(%{request | url: "form-data-body"}, opts) ==
             {:ok,
              %HTTPResponse{
                status: 200,
                headers: [{"content-type", "application/x-www-form-urlencoded"}],
                body: %{"a" => "1"},
                http_adapter: HTTPMock,
                request_url: "form-data-body"
              }}

    assert HTTPAdapter.request(%{request | url: "form-data-body-already-decoded"}, opts) ==
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
  @json_encoded_body JSON.encode!(@body)
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

  test "format_http_response/1" do
    response = %HTTPResponse{
      body: "Hello",
      headers: [{"content-type", "text/plain"}],
      http_adapter: HTTPMock,
      request_url: "http://example.com/path?a=1",
      status: 200
    }

    formatted = HTTPAdapter.format_http_response(response)
    assert formatted =~ "HTTP Adapter: #{inspect(HTTPMock)}"
    assert formatted =~ "Request URL: http://example.com/path"
    assert formatted =~ "Response status: 200"
    assert formatted =~ "Response headers:\ncontent-type: text/plain"
    assert formatted =~ "Response body:\n\"Hello\""
  end
end
