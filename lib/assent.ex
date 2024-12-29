defmodule Assent do
  @moduledoc false

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
    defexception [:expected_key, :params]

    @type t :: %__MODULE__{
            expected_key: binary(),
            params: map()
          }

    def message(exception) do
      expected_key = inspect(exception.expected_key)
      params = inspect(Map.keys(exception.params))

      "Expected #{expected_key} in params, got: #{params}"
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
