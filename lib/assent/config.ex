defmodule Assent.Config do
  @moduledoc """
  Methods to handle configurations.
  """

  defmodule MissingKeyError do
    @type t :: %__MODULE__{}

    defexception [:message]
  end

  @type t :: Keyword.t()

  @doc """
  Fetches the key value from the configuration.
  """
  @spec fetch(t(), atom()) :: {:ok, any()} | {:error, MissingKeyError.t()}
  def fetch(config, key) do
    case Keyword.fetch(config, key) do
      {:ok, value} -> {:ok, value}
      :error       -> {:error, MissingKeyError.exception("Key `:#{key}` not found in config")}
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
end
