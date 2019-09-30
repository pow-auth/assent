defmodule Assent.JWTAdapter.AssentJWT do
  @moduledoc """
  JWT adapter module for parsing JWT tokens.
  """
  alias Assent.{Config, JWTAdapter, JWTAdapter.JWT}

  @behaviour Assent.JWTAdapter

  @impl JWTAdapter
  def sign(%JWT{header: header, payload: payload}, secret, opts) do
    with {:ok, encoded_header}  <- encode_json(Map.put(header, "typ", "JWT"), opts),
         {:ok, encoded_payload} <- encode_json(payload, opts),
         {:ok, signature}       <- encode(header, "#{encoded_header}.#{encoded_payload}", secret) do

      {:ok, "#{encoded_header}.#{encoded_payload}.#{signature}"}
    end
  end

  defp encode_json(map, opts) do
    with {:ok, json_library} <- Config.fetch(opts, :json_library),
         {:ok, json} <- json_library.encode(map) do
      {:ok, Base.url_encode64(json, padding: false)}
    end
  end

  defp encode(%{"alg" => "HS256"}, message, secret) do
    encoded =
      :sha256
      |> :crypto.hmac(secret, message)
      |> Base.url_encode64(padding: false)

    {:ok, encoded}
  end
  defp encode(%{"alg" => "RS256"}, message, raw_private_key) do
    with {:ok, private_key} <- decode_raw_key(raw_private_key) do
      encoded =
        message
        |> :public_key.sign(:sha256, private_key)
        |> Base.url_encode64(padding: false)

        {:ok, encoded}
    end
  end
  defp encode(%{"alg" => alg}, _message, _secret), do: {:error, "Unsupported JWT alg #{alg}"}

  defp decode_raw_key(private_key) do
    case :public_key.pem_decode(private_key) do
      [entry] -> {:ok, :public_key.pem_entry_decode(entry)}
      _any    -> {:error, "Private key should only have one entry"}
    end
  end

  @impl JWTAdapter
  def verify(jwt, secret, opts) do
    with {:ok, token_1} <- sign(jwt, secret, opts),
         {:ok, token_2} <- Map.fetch(jwt.encoded, :jwt) do

      constant_time_compare(token_1, token_2)
    end
  end

  @impl JWTAdapter
  def decode(token, opts) do
    with {:ok, json_library} <- Config.fetch(opts, :json_library),
         {:ok, jwt} <- parse(token, json_library) do
      {:ok, jwt}
    end
  end

  defp parse(token, json_library) do
    with [header, payload, signature] <- String.split(token, "."),
         {:ok, header_json} <- Base.url_decode64(header, padding: false),
         {:ok, payload_json} <- Base.url_decode64(payload, padding: false),
         {:ok, header} <- json_library.decode(header_json),
         {:ok, payload} <- json_library.decode(payload_json) do
      {:ok, %JWT{
        header: header,
        payload: payload,
        encoded: %{
          header: header_json,
          payload: payload_json,
          signature: signature,
          jwt: token}}}
    else
      {:error, error} -> {:error, error}
      :error          -> {:error, "Couldn't decode base64 string"}
      _any            -> {:error, "The token is not a valid JWT"}
    end
  end

  use Bitwise

  defp constant_time_compare(left, right) when byte_size(left) == byte_size(right) do
    constant_time_compare(left, right, 0) == 0
  end
  defp constant_time_compare(_hash, _secret_hash), do: false

  defp constant_time_compare(<<x, left::binary>>, <<y, right::binary>>, acc) do
    xorred = x ^^^ y
    constant_time_compare(left, right, acc ||| xorred)
  end
  defp constant_time_compare(<<>>, <<>>, acc) do
    acc
  end
end
