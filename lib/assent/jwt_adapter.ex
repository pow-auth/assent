defmodule Assent.JWTAdapter do
  @moduledoc false

  alias Assent.Config

  defmodule JWT do
    @moduledoc false

    @type t :: %__MODULE__{
      header: map(),
      payload: map(),
      parts: map()
    }

    defstruct header: nil, payload: nil, parts: nil
  end

  @callback decode(binary(), Keyword.t()) :: {:ok, JWT.t()} | {:error, any()}

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
