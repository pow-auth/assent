defmodule Assent.Config do
  @moduledoc """
  Methods to handle configurations.
  """

  defmodule MissingKeyError do
    @type t :: %__MODULE__{}

    defexception [:key]

    def message(exception) do
      "Key #{inspect(exception.key)} not found in config"
    end
  end

  @type t :: Keyword.t()

  @doc """
  Fetches the key value from the configuration.
  """
  @spec fetch(t(), atom()) :: {:ok, any()} | {:error, MissingKeyError.t()}
  def fetch(config, key) do
    case Keyword.fetch(config, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, MissingKeyError.exception(key: key)}
    end
  end

  defdelegate get(config, key, default), to: Keyword

  defdelegate put(config, key, value), to: Keyword

  defdelegate merge(config_a, config_b), to: Keyword

  @doc """
  Fetches the JSON library in config.

  If not found in provided config, this will attempt to load the JSON library
  from global application environment for `:assent`. Defaults to `Jason`.
  """
  @spec json_library(t()) :: module()
  def json_library(config) do
    case get(config, :json_library, nil) do
      nil ->
        Application.get_env(:assent, :json_library, Jason)

      json_library ->
        json_library
    end
  end

  # TODO: Remove in next major version
  def __base_url__(config) do
    case fetch(config, :base_url) do
      {:ok, base_url} ->
        {:ok, base_url}

      {:error, error} ->
        case fetch(config, :site) do
          {:ok, base_url} ->
            IO.warn("The `:site` configuration key is deprecated, use `:base_url` instead")
            {:ok, base_url}

          {:error, _site_error} ->
            {:error, error}
        end
    end
  end
end
