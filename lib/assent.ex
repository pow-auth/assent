defmodule Assent do
  @moduledoc false

  defmodule CallbackError do
    defexception [:message, :error, :error_uri]
  end

  defmodule CallbackCSRFError do
    defexception [:message]

    @spec new(binary()) :: %__MODULE__{}
    def new(key) do
      %__MODULE__{message: "CSRF detected with param key #{inspect key}"}
    end
  end

  defmodule MissingParamError do
    defexception [:message, :params]

    @spec new(binary(), map()) :: %__MODULE__{}
    def new(key, params) do
      %__MODULE__{
        message: "Expected #{inspect key} to exist in params, but only found the following keys: #{inspect Map.keys(params)}",
        params: params
      }
    end
  end

  defmodule RequestError do
    defexception [:message, :error]

    alias Assent.HTTPAdapter.HTTPResponse

    @spec unexpected(HTTPResponse.t()) :: %__MODULE__{}
    def unexpected(response) do
      %__MODULE__{
        message:
          """
          An unexpected success response was received:

          #{inspect response.body}
          """,
        error: :unexpected_response
      }
    end

    @spec invalid(HTTPResponse.t()) :: %__MODULE__{}
    def invalid(response) do
      %__MODULE__{
        message:
          """
          Server responded with status: #{response.status}

          Headers:#{Enum.reduce(response.headers, "", fn {k, v}, acc -> acc <> "\n#{k}: #{v}" end)}

          Body:
          #{inspect response.body}
          """,
        error: :invalid_server_response
      }
    end

    @spec unreachable(atom(), binary(), term()) :: %__MODULE__{}
    def unreachable(adapter, url, error) do
      %__MODULE__{
        message:
          """
          Server was unreachable with #{inspect adapter}.

          Failed with the following error:
          #{inspect error}

          URL: #{url}
          """,
        error: :unreachable
      }
    end
  end

  use Bitwise

  @doc false
  @spec constant_time_compare(binary(), binary()) :: boolean()
  def constant_time_compare(left, right) when byte_size(left) == byte_size(right) do
    constant_time_compare(left, right, 0) == 0
  end
  def constant_time_compare(_hash, _secret_hash), do: false

  def constant_time_compare(<<x, left::binary>>, <<y, right::binary>>, acc) do
    xorred = x ^^^ y
    constant_time_compare(left, right, acc ||| xorred)
  end
  def constant_time_compare(<<>>, <<>>, acc) do
    acc
  end
end
