defmodule Assent.HTTPAdapter do
  @moduledoc """
  HTTP adapter helper module.

  You can configure which HTTP adapter Assent uses by setting the
  configuration:

      http_adapter: Assent.HTTPAdapter.Httpc

  Default options can be set by passing a list of options:

      http_adapter: {Assent.HTTPAdapter.Httpc, [...]}

  You can also set global application config:

      config :assent, :http_adapter, Assent.HTTPAdapter.Httpc

  ## Usage

      defmodule MyApp.MyHTTPAdapter do
        @behaviour Assent.HTTPAdapter

        @impl true
        def request(method, url, body, headers, opts) do
          # Implement your HTTP request logic here using your preferred
          # HTTP client library. Return {:ok, response} or {:error, reason}.
        end
      end
  """
  defmodule HTTPRequest do
    @moduledoc """
    Struct used by HTTP adapters to normalize HTTP requests.

    The `:url`, `:headers`, and `:body` fields are omitted from `Inspect`
    output as they may contain sensitive data.

    ## Examples

        iex> request = %Assent.HTTPAdapter.HTTPRequest{method: :get, url: "https://example.com"}
        iex> inspect(request)
        "#Assent.HTTPAdapter.HTTPRequest<method: :get, ...>"
    """

    @type t :: %__MODULE__{
            method: :get | :post,
            url: binary(),
            headers: [{binary(), binary()}],
            body: binary() | nil
          }

    @derive {Inspect, only: [:method]}
    defstruct [:method, :url, headers: [], body: nil]
  end

  defmodule HTTPResponse do
    @moduledoc """
    Struct used by HTTP adapters to normalize HTTP responses.

    The `:request`, `:headers`, and `:body` fields are omitted from `Inspect`
    output as they may contain sensitive data.

    ## Examples

        iex> response = %Assent.HTTPAdapter.HTTPResponse{
        ...>   request: %Assent.HTTPAdapter.HTTPRequest{method: :get, url: "https://example.com"},
        ...>   http_adapter: Assent.HTTPAdapter.Httpc,
        ...>   status: 200,
        ...>   body: "OK"
        ...> }
        iex> inspect(response)
        "#Assent.HTTPAdapter.HTTPResponse<http_adapter: Assent.HTTPAdapter.Httpc, status: 200, ...>"
    """

    @type header :: {binary(), binary()}
    @type t :: %__MODULE__{
            request: Assent.HTTPAdapter.HTTPRequest.t(),
            http_adapter: module(),
            status: integer(),
            headers: [header()],
            body: binary() | term()
          }

    @derive {Inspect, only: [:http_adapter, :status]}
    defstruct [:request, :http_adapter, status: 200, headers: [], body: ""]
  end

  defmodule RequestError do
    @moduledoc """
    An exception for when a provider rejects an HTTP request.

    The `:response` field is omitted from `Inspect` output as it may contain
    sensitive data.

    ## Fields

      * `:message` - a description of the error
      * `:response` - the normalized HTTP response

    ## Examples

        iex> error = %Assent.HTTPAdapter.RequestError{
        ...>   message: "Request failed",
        ...>   response: %Assent.HTTPAdapter.HTTPResponse{
        ...>     request: %Assent.HTTPAdapter.HTTPRequest{method: :get, url: "https://example.com"},
        ...>     http_adapter: Assent.HTTPAdapter.Httpc,
        ...>     status: 500,
        ...>     body: "Internal Server Error"
        ...>   }
        ...> }
        iex> Exception.message(error)
        "Request failed\\n\\nHTTP adapter: Assent.HTTPAdapter.Httpc\\nRequest: GET https://example.com\\nResponse status: 500\\n"
        iex> inspect(error)
        "#Assent.HTTPAdapter.RequestError<message: \\"Request failed\\", ...>"
    """

    @type t :: %__MODULE__{
            message: binary(),
            response: Assent.HTTPAdapter.HTTPResponse.t()
          }
    @derive {Inspect, only: [:message]}

    defexception [:message, :response]

    def message(exception) do
      "#{exception.message}\n\n#{Assent.HTTPAdapter.format_http_response(exception.response)}"
    end
  end

  defmodule InvalidResponseError do
    @moduledoc """
    An exception for when an HTTP response is invalid.

    The `:response` field is omitted from `Inspect` output as it may contain
    sensitive data.

    ## Fields

      * `:response` - the normalized HTTP response

    ## Examples

        iex> error = %Assent.HTTPAdapter.InvalidResponseError{
        ...>   response: %Assent.HTTPAdapter.HTTPResponse{
        ...>     request: %Assent.HTTPAdapter.HTTPRequest{method: :get, url: "https://example.com"},
        ...>     http_adapter: Assent.HTTPAdapter.Httpc,
        ...>     status: 500,
        ...>     body: "Internal Server Error"
        ...>   }
        ...> }
        iex> Exception.message(error)
        "invalid response\\n\\nHTTP adapter: Assent.HTTPAdapter.Httpc\\nRequest: GET https://example.com\\nResponse status: 500\\n"
        iex> inspect(error)
        "#Assent.HTTPAdapter.InvalidResponseError<...>"
    """

    @type t :: %__MODULE__{response: Assent.HTTPAdapter.HTTPResponse.t()}
    @derive {Inspect, only: []}

    defexception [:response]

    def message(exception) do
      "invalid response\n\n#{Assent.HTTPAdapter.format_http_response(exception.response)}"
    end
  end

  defmodule UnexpectedResponseError do
    @moduledoc """
    An exception for when an HTTP response is unexpected.

    The `:response` field is omitted from `Inspect` output as it may contain
    sensitive data.

    ## Fields

      * `:response` - the normalized HTTP response

    ## Examples

        iex> error = %Assent.HTTPAdapter.UnexpectedResponseError{
        ...>   response: %Assent.HTTPAdapter.HTTPResponse{
        ...>     request: %Assent.HTTPAdapter.HTTPRequest{method: :get, url: "https://example.com"},
        ...>     http_adapter: Assent.HTTPAdapter.Httpc,
        ...>     status: 500,
        ...>     body: "Internal Server Error"
        ...>   }
        ...> }
        iex> Exception.message(error)
        "unexpected response\\n\\nHTTP adapter: Assent.HTTPAdapter.Httpc\\nRequest: GET https://example.com\\nResponse status: 500\\n"
        iex> inspect(error)
        "#Assent.HTTPAdapter.UnexpectedResponseError<...>"
    """

    @type t :: %__MODULE__{response: Assent.HTTPAdapter.HTTPResponse.t()}
    @derive {Inspect, only: []}

    defexception [:response]

    def message(exception) do
      "unexpected response\n\n#{Assent.HTTPAdapter.format_http_response(exception.response)}"
    end
  end

  defmodule ServerUnreachableError do
    @moduledoc """
    An exception for when a server is unreachable.

    The `:request` and `:reason` fields are omitted from `Inspect` output as
    they may contain sensitive data.

    ## Fields

      * `:http_adapter` - the HTTP adapter module
      * `:request` - the HTTP request
      * `:reason` - the underlying failure reason

    ## Examples

        iex> error = %Assent.HTTPAdapter.ServerUnreachableError{
        ...>   http_adapter: Assent.HTTPAdapter.Httpc,
        ...>   request: %Assent.HTTPAdapter.HTTPRequest{method: :get, url: "https://example.com"},
        ...>   reason: :timeout
        ...> }
        iex> Exception.message(error)
        "server is unreachable\\n\\nHTTP adapter: Assent.HTTPAdapter.Httpc\\nRequest: GET https://example.com\\n"
        iex> inspect(error)
        "#Assent.HTTPAdapter.ServerUnreachableError<http_adapter: Assent.HTTPAdapter.Httpc, ...>"
    """

    @type t :: %__MODULE__{
            http_adapter: module(),
            request: Assent.HTTPAdapter.HTTPRequest.t(),
            reason: term()
          }

    @derive {Inspect, only: [:http_adapter]}

    defexception [:http_adapter, :request, :reason]

    def message(exception) do
      "server is unreachable\n\n" <>
        "HTTP adapter: #{inspect(exception.http_adapter)}\n" <>
        Assent.HTTPAdapter.format_http_request(exception.request)
    end
  end

  @type method :: :get | :post
  @type body :: binary() | nil
  @type headers :: [{binary(), binary()}]

  @doc """
  Sends an HTTP request using the adapter's client.
  """
  @callback request(method(), binary(), body(), headers(), Keyword.t()) ::
              {:ok, HTTPResponse.t()} | {:error, term()}

  @doc """
  Sets a user agent header.

  The header value will be `Assent-VERSION` with VERSION being the `:vsn` of
  `:assent` app.
  """
  @spec user_agent_header() :: {binary(), binary()}
  def user_agent_header do
    version = Application.spec(:assent, :vsn) || "0.0.0"

    {"User-Agent", "Assent-#{version}"}
  end

  @doc """
  Makes an HTTP request.

  ## Options

    * `:http_adapter` - HTTP adapter configuration. Defaults to
      `{Assent.HTTPAdapter.Req, []}`, `{Assent.HTTPAdapter.Httpc, []}`
      depending on which HTTP client is available in the project dependencies.

    * `:json_library` - the JSON library to use, see `Assent.json_library/1`
  """
  @spec request(HTTPRequest.t(), Keyword.t()) ::
          {:ok, HTTPResponse.t()} | {:error, HTTPResponse.t()} | {:error, term()}
  def request(%HTTPRequest{} = request, opts) do
    {http_adapter, http_adapter_opts} = get_http_adapter(opts)

    request.method
    |> http_adapter.request(request.url, request.body, request.headers, http_adapter_opts)
    |> case do
      {:ok, response} ->
        %{response | request: request, http_adapter: http_adapter}
        |> normalize_headers()
        |> decode_response(opts)

      {:error, error} ->
        {:error,
         ServerUnreachableError.exception(
           http_adapter: http_adapter,
           request: request,
           reason: error
         )}
    end
    |> case do
      {:ok, %{status: status} = response} when status in 200..399 ->
        {:ok, response}

      {:ok, %{status: status} = response} when status in 400..599 ->
        {:error, response}

      {:error, error} ->
        {:error, error}
    end
  end

  @deprecated "Use `request/2` instead. This will be removed in v1.0.0."
  def request(method, url, body, headers, opts) do
    request(%HTTPRequest{method: method, url: url, headers: headers, body: body}, opts)
  end

  defp get_http_adapter(opts) do
    case Keyword.get_lazy(opts, :http_adapter, fn ->
           Application.get_env(:assent, :http_adapter) || default_http_adapter()
         end) do
      {mod, server_options} when is_atom(mod) and is_list(server_options) -> {mod, server_options}
      mod when is_atom(mod) -> {mod, []}
      other -> raise("Invalid http_adapter, got: #{inspect(other)}")
    end
  end

  defp default_http_adapter do
    case Code.ensure_loaded?(Assent.HTTPAdapter.Req) do
      true -> {Assent.HTTPAdapter.Req, []}
      false -> {Assent.HTTPAdapter.Httpc, []}
    end
  end

  defp normalize_headers(%HTTPResponse{headers: headers} = response) do
    %{response | headers: Enum.map(headers, fn {key, value} -> {String.downcase(key), value} end)}
  end

  @doc """
  Decodes request response body.

  ## Options

    * `:json_library` - the JSON library to use, see `Assent.json_library/1`
  """
  @spec decode_response(HTTPResponse.t(), Keyword.t()) ::
          {:ok, HTTPResponse.t()} | {:error, InvalidResponseError.t()}
  def decode_response(%HTTPResponse{} = response, opts) do
    case decode(response.headers, response.body, opts) do
      {:ok, body} -> {:ok, %{response | body: body}}
      {:error, _error} -> {:error, InvalidResponseError.exception(response: response)}
    end
  end

  defp decode(headers, body, opts) when is_binary(body) do
    case List.keyfind(headers, "content-type", 0) do
      {"content-type", "application/json" <> _rest} ->
        Assent.json_library(opts).decode(body)

      {"content-type", "text/javascript" <> _rest} ->
        Assent.json_library(opts).decode(body)

      {"content-type", "application/x-www-form-urlencoded" <> _reset} ->
        {:ok, URI.decode_query(body)}

      _any ->
        {:ok, body}
    end
  end

  defp decode(_headers, body, _opts), do: {:ok, body}

  @doc """
  Formats an HTTP request for an error message.
  """
  @spec format_http_request(HTTPRequest.t()) :: binary()
  def format_http_request(request) do
    uri = URI.parse(request.url)
    url = URI.to_string(%{uri | fragment: nil, query: nil, userinfo: nil})

    "Request: #{String.upcase(to_string(request.method))} #{url}\n"
  end

  @doc """
  Formats an HTTP response for an error message.
  """
  @spec format_http_response(HTTPResponse.t()) :: binary()
  def format_http_response(response) do
    """
    HTTP adapter: #{inspect(response.http_adapter)}
    #{format_http_request(response.request)}\
    Response status: #{response.status}
    """
  end
end
