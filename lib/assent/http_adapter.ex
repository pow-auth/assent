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
  Sets a user agent header

  The header value will be `Assent-VERSION` with VERSION being the `:vsn` of
  `:assent` app.
  """
  @spec user_agent_header() :: {binary(), binary()}
  def user_agent_header do
    version = Application.spec(:assent, :vsn) || "0.0.0"

    {"User-Agent", "Assent-#{version}"}
  end
end
