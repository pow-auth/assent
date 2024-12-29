defmodule Assent do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()
             |> String.split("<!-- MDOC !-->")
             |> Enum.fetch!(1)

  defmodule MissingConfigError do
    defexception [:key, :config]

    @type t :: %__MODULE__{
            key: atom(),
            config: Keyword.t()
          }

    def message(exception) do
      key = inspect(exception.key)
      config_keys = inspect(Keyword.keys(exception.config))

      "Expected #{key} in config, got: #{config_keys}"
    end
  end

  defmodule CallbackError do
    defexception [:message, :error, :error_uri]
  end

  defmodule CallbackCSRFError do
    defexception [:key]

    @type t :: %__MODULE__{
            key: binary()
          }

    def message(exception) do
      "CSRF detected with param key #{inspect(exception.key)}"
    end
  end

  defmodule MissingParamError do
    defexception [:key, :params]

    @type t :: %__MODULE__{
            key: binary(),
            params: map()
          }

    # TODO: Deprecated, remove in 0.3
    def exception(opts) do
      opts =
        case Keyword.fetch(opts, :expected_key) do
          {:ok, key} ->
            IO.warn("The `expected_key` option is deprecated. Please use `key` instead.")
            [key: key, params: opts[:params]]

          :error ->
            opts
        end

      struct!(__MODULE__, opts)
    end

    def message(exception) do
      key = inspect(exception.key)
      param_keys = exception.params |> Map.keys() |> Enum.sort() |> inspect()

      "Expected #{key} in params, got: #{param_keys}"
    end
  end

  defmodule RequestError do
    defexception [:message, :response]

    alias Assent.HTTPAdapter.HTTPResponse

    @type t :: %__MODULE__{
            message: binary(),
            response: HTTPResponse.t()
          }

    def message(exception) do
      """
      #{exception.message}

      #{HTTPResponse.format(exception.response)}
      """
    end
  end

  defmodule InvalidResponseError do
    defexception [:response]

    alias Assent.HTTPAdapter.HTTPResponse

    @type t :: %__MODULE__{
            response: HTTPResponse.t()
          }

    def message(exception) do
      """
      An invalid response was received.

      #{HTTPResponse.format(exception.response)}
      """
    end
  end

  defmodule UnexpectedResponseError do
    defexception [:response]

    alias Assent.HTTPAdapter.HTTPResponse

    @type t :: %__MODULE__{
            response: HTTPResponse.t()
          }

    def message(exception) do
      """
      An unexpected response was received.

      #{HTTPResponse.format(exception.response)}
      """
    end
  end

  defmodule ServerUnreachableError do
    defexception [:http_adapter, :request_url, :reason]

    @type t :: %__MODULE__{
            http_adapter: module(),
            request_url: binary(),
            reason: term()
          }

    def message(exception) do
      [url | _rest] = String.split(exception.request_url, "?", parts: 2)

      """
      The server was unreachable.

      HTTP Adapter: #{inspect(exception.http_adapter)}
      Request URL: #{url}

      Reason:
      #{inspect(exception.reason)}
      """
    end
  end

  @doc """
  Fetches the key value from the configuration.

  Returns a `Assent.MissingConfigError` if the key is not found.
  """
  @spec fetch_config(Keyword.t(), atom()) :: {:ok, any()} | {:error, MissingConfigError.t()}
  def fetch_config(config, key) when is_list(config) and is_atom(key) do
    case Keyword.fetch(config, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, MissingConfigError.exception(key: key, config: config)}
    end
  end

  @doc """
  Fetches the key value from the params.

  Returns a `Assent.MissingParamError` if the key is not found.
  """
  @spec fetch_param(map(), binary()) :: {:ok, any()} | {:error, MissingParamError.t()}
  def fetch_param(params, key) when is_map(params) and is_binary(key) do
    case Map.fetch(params, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, MissingParamError.exception(key: key, params: params)}
    end
  end

  @default_json_library (Code.ensure_loaded?(JSON) && JSON) || Jason

  @doc """
  Fetches the JSON library in config.

  If not found in provided config, this will attempt to load the JSON library
  from global application environment for `:assent`. Defaults to
  `#{inspect(@default_json_library)}`.
  """
  @spec json_library(Keyword.t()) :: module()
  def json_library(config) do
    case Keyword.fetch(config, :json_library) do
      :error -> Application.get_env(:assent, :json_library, @default_json_library)
      {:ok, json_library} -> json_library
    end
  end

  import Bitwise

  @doc false
  @spec constant_time_compare(binary(), binary()) :: boolean()
  def constant_time_compare(left, right) when is_binary(left) and is_binary(right) do
    byte_size(left) == byte_size(right) and constant_time_compare(left, right, 0)
  end

  defp constant_time_compare(<<x, left::binary>>, <<y, right::binary>>, acc) do
    xorred = bxor(x, y)
    constant_time_compare(left, right, acc ||| xorred)
  end

  defp constant_time_compare(<<>>, <<>>, acc) do
    acc === 0
  end
end
