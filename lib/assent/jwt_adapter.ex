defmodule Assent.JWTAdapter do
  @moduledoc """
  JWT adapter helper module.

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

  @callback sign(map(), binary(), binary(), Keyword.t()) :: {:ok, binary()} | {:error, any()}
  @callback verify(binary(), binary() | map() | nil, Keyword.t()) :: {:ok, map()} | {:error, any()}

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

    case Keyword.get(opts, :jwt_adapter, Assent.JWTAdapter.AssentJWT) do
      {adapter, opts} -> {adapter, Keyword.merge(default_opts, opts)}
      adapter         -> {adapter, default_opts}
    end
  end

  @doc """
  Loads a private key from the provided configuration
  """
  @spec load_private_key(Config.t()) :: {:ok, binary()} | {:error, term()}
  def load_private_key(config) do
    case Config.fetch(config, :private_key_path) do
      {:ok, path}    -> File.read(path)
      {:error, _any} -> Config.fetch(config, :private_key)
    end
  end
end
