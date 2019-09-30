defmodule Assent.JWTAdapter.AssentJWT do
  @moduledoc """
  JWT adapter module for parsing JWT tokens.
  """
  alias Assent.{Config, JWTAdapter, JWTAdapter.JWT}

  @behaviour Assent.JWTAdapter

  @impl JWTAdapter
  def sign(%JWT{header: header, payload: payload}, secret, opts) do
    with {:ok, encoded_header}  <- encode_json_base64(Map.put(header, "typ", "JWT"), opts),
         {:ok, encoded_payload} <- encode_json_base64(payload, opts),
         {:ok, signature}       <- sign_message(header, "#{encoded_header}.#{encoded_payload}", secret) do

      encoded_signature = Base.url_encode64(signature, padding: false)

      {:ok, "#{encoded_header}.#{encoded_payload}.#{encoded_signature}"}
    end
  end

  defp encode_json_base64(map, opts) do
    with {:ok, json_library} <- Config.fetch(opts, :json_library),
         {:ok, json} <- json_library.encode(map) do
      {:ok, Base.url_encode64(json, padding: false)}
    end
  end

  defp sign_message(%{"alg" => "HS" <> sha_bit_size}, message, secret) do
    with {:ok, sha_alg} <- sha2_alg(sha_bit_size) do
      {:ok, :crypto.hmac(sha_alg, secret, message)}
    end
  end
  defp sign_message(%{"alg" => <<_, "S", sha_bit_size :: binary>>}, message, raw_private_key) do
    with {:ok, sha_alg} <- sha2_alg(sha_bit_size),
         {:ok, private_key} <- decode_raw_key(raw_private_key) do

      {:ok, :public_key.sign(message, sha_alg, private_key)}
    end
  end
  defp sign_message(%{"alg" => alg}, _message, _secret), do: {:error, "Unsupported JWT alg #{alg}"}

  defp sha2_alg("256"), do: {:ok, :sha256}
  defp sha2_alg("384"), do: {:ok, :sha384}
  defp sha2_alg("512"), do: {:ok, :sha512}
  defp sha2_alg(bit_size), do: {:error, "Invalid SHA-2 algorithm bit size: #{bit_size}"}

   defp decode_raw_key(private_key) do
    case :public_key.pem_decode(private_key) do
      [entry] -> {:ok, :public_key.pem_entry_decode(entry)}
      _any    -> {:error, "Private key should only have one entry"}
    end
  end

  @impl JWTAdapter
  def verify(%JWT{header: header, encoded: %{header: header_json, payload: payload_json, signature: signature}}, secret, _opts) do
    encoded_header  = Base.url_encode64(header_json, padding: false)
    encoded_payload = Base.url_encode64(payload_json, padding: false)

    verify_message(header, "#{encoded_header}.#{encoded_payload}", signature, secret)
  end

  defp verify_message(%{"alg" => "HS" <> _rest} = header, message, signature, secret) do
    case sign_message(header, message, secret) do
      {:ok, signature_2} -> constant_time_compare(signature_2, signature)
      _any               -> false
    end
  end
  defp verify_message(%{"alg" => <<_, "S", sha_bit_size :: binary>>}, message, signature, secret) do
    with {:ok, sha_alg} <- sha2_alg(sha_bit_size),
         {:ok, public_key} <- decode_raw_key(secret) do
      :public_key.verify(message, sha_alg, signature, public_key)
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
         {:ok, signature} <- Base.url_decode64(signature, padding: false),
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
