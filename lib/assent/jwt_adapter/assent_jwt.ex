defmodule Assent.JWTAdapter.AssentJWT do
  @moduledoc """
  JWT adapter module for parsing JWT tokens.
  """
  alias Assent.{Config, JWTAdapter, JWTAdapter.JWT}

  @behaviour Assent.JWTAdapter

  @impl JWTAdapter
  def decode(token, opts) do
    with {:ok, json_library} <- Config.fetch(opts, :json_library),
         {:ok, jwt} <- parse(token, json_library) do
      {:ok, jwt}
    end
  end

  defp parse(token, json_library) do
    with [header, payload, signature] <- String.split(token, "."),
         {:ok, header_json} <- Base.decode64(header, padding: false),
         {:ok, payload_json} <- Base.decode64(payload, padding: false),
         {:ok, header} <- json_library.decode(header_json),
         {:ok, payload} <- json_library.decode(payload_json) do
      {:ok, %JWT{
        header: header,
        payload: payload,
        parts: [
          header: header_json,
          payload: payload_json,
          signature: signature]}}
    else
      {:error, error} -> {:error, error}
      :error          -> {:error, "Couldn't decode base64 string"}
      _any            -> {:error, "The token is not a JWT"}
    end
  end
end
