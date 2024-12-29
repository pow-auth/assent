# TODO: Deprecated, remove in 0.3
defmodule Assent.Config do
  @moduledoc false

  defmodule MissingConfigError do
    @type t :: %__MODULE__{}

    defexception [:key]

    def message(exception) do
      "Key #{inspect(exception.key)} not found in config"
    end
  end

  @type t :: Keyword.t()

  @doc false
  @deprecated "Use Assent.fetch_config/2 instead"
  def fetch(config, key), do: Assent.fetch_config(config, key)

  @deprecated "Use Keyword.get/3 instead"
  defdelegate get(config, key, default), to: Keyword

  @deprecated "Use Keyword.put/3 instead"
  defdelegate put(config, key, value), to: Keyword

  @deprecated "Use Keyword.merge/2 instead"
  defdelegate merge(config_a, config_b), to: Keyword

  @deprecated "Use Assent.json_library/1 instead"
  def json_library(config), do: Assent.json_library(config)

  def __base_url__(config) do
    case Assent.fetch_config(config, :base_url) do
      {:ok, base_url} ->
        {:ok, base_url}

      {:error, error} ->
        case Assent.fetch_config(config, :site) do
          {:ok, base_url} ->
            IO.warn("The `:site` configuration key is deprecated, use `:base_url` instead")
            {:ok, base_url}

          {:error, _site_error} ->
            {:error, error}
        end
    end
  end
end
