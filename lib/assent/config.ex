defmodule Assent.Config do
  @moduledoc """
  Methods to handle configurations.
  """

  defmodule MissingKeyError do
    defexception [:message]
  end

  @type t :: Keyword.t()

  @doc """
  Fetches the key value from the configuration.
  """
  @spec fetch(t(), atom()) :: {:ok, any()} | {:error, %MissingKeyError{}}
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

  If not found in provided config, this will attempt to load the json library
  from global application environment for `:assent` or `:phoenix`. Defaults to
  `Poison`.
  """
  @spec json_library(t()) :: module()
  def json_library(config) do
    config
    |> get(:json_library, nil)
    |> Kernel.||(Application.get_env(:assent, :json_library))
    |> Kernel.||(Application.get_env(:phoenix, :json_library, Poison))
  end
end
