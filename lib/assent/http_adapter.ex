defmodule Assent.HTTPAdapter do
  @moduledoc """
  HTTP adapter helper module.

  You can configure the which HTTP adapter Assent uses by setting the
  configuring:

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
          # ...
        end
      end
  """
  alias Assent.{InvalidResponseError, ServerUnreachableError}

  defmodule HTTPResponse do
    @moduledoc """
    Struct used by HTTP adapters to normalize HTTP responses.
    """

    @type header :: {binary(), binary()}
    @type t :: %__MODULE__{
            http_adapter: atom(),
            request_url: binary(),
            status: integer(),
            headers: [header()],
            body: binary() | term()
          }

    defstruct http_adapter: nil, request_url: nil, status: 200, headers: [], body: ""

    def format(response) do
      [request_url | _rest] = String.split(response.request_url, "?", parts: 2)

      """
      HTTP Adapter: #{inspect(response.http_adapter)}
      Request URL: #{request_url}

      Response status: #{response.status}

      Response headers:
      #{Enum.reduce(response.headers, "", fn {k, v}, acc -> acc <> "\n#{k}: #{v}" end)}

      Response body:
      #{inspect(response.body)}
      """
    end
  end

  @type method :: :get | :post
  @type body :: binary() | nil
  @type headers :: [{binary(), binary()}]

  @callback request(method(), binary(), body(), headers(), Keyword.t()) ::
              {:ok, map()} | {:error, any()}

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

  @default_http_client Enum.find_value(
                         [
                           {Req, Assent.HTTPAdapter.Req},
                           {:httpc, Assent.HTTPAdapter.Httpc}
                         ],
                         fn {dep, module} ->
                           Code.ensure_loaded?(dep) && {module, []}
                         end
                       )

  @doc """
  Makes a HTTP request.

  ## Options

  - `:http_adapter` - The HTTP adapter to use, defaults to
    `#{inspect(elem(@default_http_client, 0))}`.
  - `:json_library` - The JSON library to use, see
    `Assent.json_library/1`.
  """
  @spec request(atom(), binary(), binary() | nil, list(), Keyword.t()) ::
          {:ok, HTTPResponse.t()} | {:error, HTTPResponse.t()} | {:error, term()}
  def request(method, url, body, headers, opts) do
    {http_adapter, http_adapter_opts} = get_adapter(opts)

    method
    |> http_adapter.request(url, body, headers, http_adapter_opts)
    |> case do
      {:ok, response} ->
        decode_response(response, opts)

      {:error, error} ->
        {:error,
         ServerUnreachableError.exception(
           reason: error,
           http_adapter: http_adapter,
           request_url: url
         )}
    end
    |> case do
      {:ok, %{status: status} = resp} when status in 200..399 ->
        {:ok, %{resp | http_adapter: http_adapter, request_url: url}}

      {:ok, %{status: status} = resp} when status in 400..599 ->
        {:error, %{resp | http_adapter: http_adapter, request_url: url}}

      {:error, error} ->
        {:error, error}
    end
  end

  defp get_adapter(opts) do
    default_http_adapter = Application.get_env(:assent, :http_adapter, @default_http_client)

    case Keyword.get(opts, :http_adapter, default_http_adapter) do
      {http_adapter, opts} -> {http_adapter, opts}
      http_adapter when is_atom(http_adapter) -> {http_adapter, nil}
    end
  end

  @doc """
  Decodes request response body.

  ## Options

  - `:json_library` - The JSON library to use, see
    `Assent.json_library/1`
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
end
