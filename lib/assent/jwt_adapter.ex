defmodule Assent.JWTAdapter do
  @moduledoc """
  JWT adapter helper module.

  You can configure which JWT adapter Assent uses by setting the configuration:

      jwt_adapter: Assent.JWTAdapter.AssentJWT

  Default options can be set by passing a list of options:

      jwt_adapter: {Assent.JWTAdapter.AssentJWT, [...]}

  You can also set global application config:

      config :assent, :jwt_adapter, Assent.JWTAdapter.AssentJWT

  ## Usage

      defmodule MyApp.MyJWTAdapter do
        @behaviour Assent.JWTAdapter

        @impl true
        def sign(claims, alg, secret, opts) do
          # Implement your JWT signing logic here. Return {:ok, token}.
        end

        @impl true
        def verify(token, secret, opts) do
          # Implement your JWT verification logic here. Return {:ok, claims}.
        end
      end
  """
  @callback sign(map(), binary(), binary(), Keyword.t()) :: {:ok, binary()} | {:error, term()}
  @callback verify(binary(), binary() | map() | nil, Keyword.t()) ::
              {:ok, map()} | {:error, term()}

  @default_jwt_adapter Assent.JWTAdapter.AssentJWT

  @doc """
  Generates a signed JSON Web Token signature.

  ## Options

    * `:json_library` - the JSON library to use, optional, see
      `Assent.json_library/1`

    * `:jwt_adapter` - the JWT adapter module to use, optional, defaults to
      `#{inspect(@default_jwt_adapter)}`

  ## Examples

      iex> Assent.JWTAdapter.sign(%{"sub" => "123"}, "HS256", "secret")
      {:ok, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.jROrizwXV3Yj14Ofaz1zAq07YgNrxjQNyL-0slLq5Tw"}
  """
  @spec sign(map(), binary(), binary(), Keyword.t()) :: {:ok, binary()} | {:error, term()}
  def sign(claims, alg, secret, opts \\ []) do
    {adapter, opts} = get_adapter(opts)
    adapter.sign(claims, alg, secret, opts)
  end

  @doc """
  Verifies the JSON Web Token signature.

  ## Options

    * `:json_library` - the JSON library to use, optional, see
      `Assent.json_library/1`

    * `:jwt_adapter` - the JWT adapter module to use, optional, defaults to
      `#{inspect(@default_jwt_adapter)}`

  ## Examples

      iex> {:ok, jwt} = Assent.JWTAdapter.verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.jROrizwXV3Yj14Ofaz1zAq07YgNrxjQNyL-0slLq5Tw", "secret")
      iex> jwt.verified?
      true
      iex> jwt.claims
      %{"sub" => "123"}
  """
  @spec verify(binary(), binary() | map() | nil, Keyword.t()) :: {:ok, map()} | {:error, any()}
  def verify(token, secret, opts \\ []) do
    {adapter, opts} = get_adapter(opts)
    adapter.verify(token, secret, opts)
  end

  defp get_adapter(opts) do
    default_opts = Keyword.put(opts, :json_library, Assent.json_library(opts))
    default_jwt_adapter = Application.get_env(:assent, :jwt_adapter, @default_jwt_adapter)

    case Keyword.get(opts, :jwt_adapter, default_jwt_adapter) do
      {adapter, opts} -> {adapter, Keyword.merge(default_opts, opts)}
      adapter when is_atom(adapter) -> {adapter, default_opts}
    end
  end

  @doc """
  Decodes PEM encoded keys.
  """
  @spec decode_pem(binary()) :: {:ok, term()} | {:error, Exception.t()}
  def decode_pem(pem) do
    case :public_key.pem_decode(pem) do
      [entry] ->
        {:ok, :public_key.pem_entry_decode(entry)}

      [] ->
        {:error, ArgumentError.exception("expected one PEM entry, got none")}

      entries ->
        {:error, ArgumentError.exception("expected one PEM entry, got #{length(entries)}")}
    end
  end

  @doc """
  Loads a private key from the provided configuration.

  ## Options

    * `:private_key_path` - the path to the private key file, optional

    * `:private_key` - the private key content, required if `:private_key_path`
      is not set
  """
  @spec load_private_key(Keyword.t()) :: {:ok, binary()} | {:error, term()}
  def load_private_key(config) do
    case Assent.fetch_config(config, :private_key_path) do
      {:ok, path} -> read(path)
      {:error, _any} -> Assent.fetch_config(config, :private_key)
    end
  end

  defp read(path) do
    case File.read(path) do
      {:error, reason} ->
        {:error, File.Error.exception(action: "read file", path: path, reason: reason)}

      {:ok, content} ->
        {:ok, content}
    end
  end
end
