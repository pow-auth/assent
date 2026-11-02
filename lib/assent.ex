defmodule Assent do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()
             |> String.split("<!-- MDOC !-->")
             |> Enum.fetch!(1)
             # Replace Markdown-linked HexDocs cross-references with plain
             # references so ExDoc can resolve links correctly.
             |> then(&Regex.replace(~r/\[(`[^`]+`)\]\([^)]+\)/, &1, "\\1"))

  defmodule MissingConfigError do
    @moduledoc """
    An exception for when a required configuration key is missing.

    The `:config` field is omitted from `Inspect` output as it may contain
    sensitive data.

    ## Fields

      * `:key` - the missing configuration key
      * `:config` - the original configuration

    ## Examples

        iex> {:error, error} = Assent.fetch_config([client_secret: "secret"], :client_id)
        iex> Exception.message(error)
        "expected :client_id in config, got: [:client_secret]"
        iex> inspect(error)
        "#Assent.MissingConfigError<key: :client_id, ...>"
    """

    @derive {Inspect, only: [:key]}
    defexception [:key, :config]

    @type t :: %__MODULE__{
            key: atom(),
            config: Keyword.t()
          }

    def message(exception) do
      key = inspect(exception.key)
      config_keys = inspect(Keyword.keys(exception.config))

      "expected #{key} in config, got: #{config_keys}"
    end
  end

  defmodule MissingParamError do
    @moduledoc """
    An exception for when a required parameter is missing.

    The `:params` field is omitted from `Inspect` output as it may contain
    sensitive data.

    ## Fields

      * `:key` - the missing parameter name
      * `:params` - the original parameters
      * `:source` - whether the parameters came from regular params or a token

    ## Examples

        iex> {:error, error} = Assent.fetch_token_param(%{"access_token" => "secret"}, "refresh_token")
        iex> Exception.message(error)
        "expected \\\"refresh_token\\\" in token, got: [\\\"access_token\\\"]"
        iex> inspect(error)
        "#Assent.MissingParamError<key: \\"refresh_token\\", source: :token, ...>"
    """
    @type t :: %__MODULE__{key: binary(), params: map(), source: :params | :token}
    @derive {Inspect, only: [:key, :source]}

    defexception [:key, :params, :source]

    def message(exception) do
      keys = exception.params |> Map.keys() |> Enum.sort()

      "expected #{inspect(exception.key)} in #{exception.source}, got: #{inspect(keys)}"
    end
  end

  @doc """
  Fetches the key value from the configuration.

  Returns an `Assent.MissingConfigError` if the key is not found.
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

  Returns an `Assent.MissingParamError` if the key is not found.
  """
  @spec fetch_param(map(), binary()) :: {:ok, any()} | {:error, MissingParamError.t()}
  def fetch_param(params, key), do: do_fetch_param(params, key, :params)

  defp do_fetch_param(params, key, source) do
    case Map.fetch(params, key) do
      {:ok, value} ->
        {:ok, value}

      :error ->
        {:error, MissingParamError.exception(key: key, params: params, source: source)}
    end
  end

  @doc """
  Fetches the key value from the token.

  Returns an `Assent.MissingParamError` if the key is not found.
  """
  @spec fetch_token_param(map(), binary()) :: {:ok, any()} | {:error, MissingParamError.t()}
  def fetch_token_param(token, key), do: do_fetch_param(token, key, :token)

  @doc """
  Fetches the JSON library in config.

  If not found in provided config, this will attempt to load the JSON library
  from global application environment for `:assent`. Defaults to `JSON`.
  """
  @spec json_library(Keyword.t()) :: module()
  def json_library(config) do
    case Keyword.fetch(config, :json_library) do
      :error -> Application.get_env(:assent, :json_library, JSON)
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
