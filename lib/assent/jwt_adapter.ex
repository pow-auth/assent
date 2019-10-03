defmodule Assent.JWTAdapter do
  @moduledoc false

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
end
