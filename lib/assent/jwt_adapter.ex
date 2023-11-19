defmodule Assent.JWTAdapter do
  @moduledoc """
  JWT adapter helper module.

  You can configure the JWT adapter by updating the configuration:

      jwt_adapter: {Assent.JWTAdapter.AssentJWT, [...]}

  Default options can be set by passing a list of options:

      jwt_adapter: {Assent.JWTAdapter.AssentJWT, [...]}

  You can also set global application config:

      config :assent, :jwt_adapter, Assent.JWTAdapter.AssentJWT

  ## Usage

      defmodule MyApp.MyJWTAdapter do
        @behaviour Assent.JWTAdapter

        @impl true
        def sign(claims, alg, secret, opts) do
          # ...
        end

        @impl true
        def verify(token, secret, opts) do
          # ...
        end
      end
  """

  alias Assent.Config

  @callback sign(map(), binary(), binary(), Keyword.t()) :: {:ok, binary()} | {:error, term()}
  @callback verify(binary(), binary() | map() | nil, Keyword.t()) ::
              {:ok, map()} | {:error, term()}

  @doc """
  Generates a signed JSON Web Token signature
  """
  @spec sign(map(), binary(), binary(), Keyword.t()) :: {:ok, binary()} | {:error, term()}
  def sign(claims, alg, secret, opts \\ []) do
    {adapter, opts} = fetch_adapter(opts)
    adapter.sign(claims, alg, secret, opts)
  end

  @doc """
  Verifies the JSON Web Token signature
  """
  @spec verify(binary(), binary() | map() | nil, Keyword.t()) :: {:ok, map()} | {:error, any()}
  def verify(token, secret, opts \\ []) do
    {adapter, opts} = fetch_adapter(opts)
    adapter.verify(token, secret, opts)
  end

  defp fetch_adapter(opts) do
    default_opts = Keyword.put(opts, :json_library, Config.json_library(opts))
    default_jwt_adapter = Application.get_env(:assent, :jwt_adapter, Assent.JWTAdapter.AssentJWT)

    case Keyword.get(opts, :jwt_adapter, default_jwt_adapter) do
      {adapter, opts} -> {adapter, Keyword.merge(default_opts, opts)}
      adapter when is_atom(adapter) -> {adapter, default_opts}
    end
  end

  @doc """
  Loads a private key from the provided configuration
  """
  @spec load_private_key(Config.t()) :: {:ok, binary()} | {:error, term()}
  def load_private_key(config) do
    case Config.fetch(config, :private_key_path) do
      {:ok, path} -> read(path)
      {:error, _any} -> Config.fetch(config, :private_key)
    end
  end

  defp read(path) do
    case File.read(path) do
      {:error, error} -> {:error, "Failed to read \"#{path}\", got; #{inspect(error)}"}
      {:ok, content} -> {:ok, content}
    end
  end
end
