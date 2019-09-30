defmodule Assent.JWTAdapter do
  @moduledoc false

  alias Assent.Config

  defmodule JWT do
    @moduledoc false

    @type t :: %__MODULE__{
      header: map(),
      payload: map(),
      encoded: %{
        header: binary(),
        payload: binary(),
        signature: binary(),
        jwt: binary()
      } | nil
    }

    defstruct header: nil, payload: nil, encoded: nil
  end

  @callback sign(JWT.t(), binary() | {binary(), binary()}, Keyword.t()) :: {:ok, binary()} | {:error, any()}
  @callback verify(JWT.t(), binary(), Keyword.t()) :: boolean()
  @callback decode(binary(), Keyword.t()) :: {:ok, JWT.t()} | {:error, any()}


  @doc """
  Generates a signed JSON Web Token signature
  """
  @spec sign(JWT.t(), binary() | {binary(), binary()}, Keyword.t()) :: {:ok, binary()} | {:error, term()}
  def sign(jwt, secret, opts \\ []) do
    {adapter, opts} = fetch_adapter(opts)
    adapter.sign(jwt, secret, opts)
  end

  @doc """
  Verifies the JSON Web Token signature
  """
  @spec verify(JWT.t(), binary(), Keyword.t()) :: boolean()
  def verify(jwt, secret, opts \\ []) do
    {adapter, opts} = fetch_adapter(opts)
    adapter.verify(jwt, secret, opts)
  end

  @doc """
  Decodes a JSON Web Token
  """
  @spec decode(binary(), Keyword.t()) :: {:ok, JWT.t()} | {:error, term()}
  def decode(token, opts \\ []) do
    {adapter, opts} = fetch_adapter(opts)
    adapter.decode(token, opts)
  end

  defp fetch_adapter(opts) do
    default_opts = [json_library: Config.json_library(opts)]

    case Keyword.get(opts, :jwt_adapter, Assent.JWTAdapter.AssentJWT) do
      {adapter, opts} -> {adapter, Keyword.merge(default_opts, opts)}
      adapter         -> {adapter, default_opts}
    end
  end
end
