defmodule Assent.JWTAdapter.AssentJWT do
  @moduledoc """
  JWT adapter module for parsing JSON Web Tokens natively.

  See `Assent.JWTAdapter` for more.
  """
  alias Assent.{Config, JWTAdapter}

  @behaviour Assent.JWTAdapter

  @impl JWTAdapter
  def sign(claims, alg, secret_or_private_key, opts) do
    header = jws(alg, opts)

    with {:ok, encoded_header} <- encode_json_base64(header, opts),
         {:ok, encoded_claims} <- encode_json_base64(claims, opts),
         {:ok, signature}      <- sign_message("#{encoded_header}.#{encoded_claims}", alg, secret_or_private_key) do

      encoded_signature = Base.url_encode64(signature, padding: false)

      {:ok, "#{encoded_header}.#{encoded_claims}.#{encoded_signature}"}
    end
  end

  defp jws(alg, opts) do
    jws = %{"typ" => "JWT", "alg" => alg}

    case Keyword.get(opts, :private_key_id) do
      nil -> jws
      kid -> Map.put(jws, "kid", kid)
    end
  end

  defp encode_json_base64(map, opts) do
    with {:ok, json_library} <- Config.fetch(opts, :json_library),
         {:ok, json} <- json_library.encode(map) do
      {:ok, Base.url_encode64(json, padding: false)}
    end
  end

  defp sign_message(message, "HS" <> sha_bit_size, secret) do
    with {:ok, sha_alg} <- sha2_alg(sha_bit_size) do
      {:ok, :crypto.mac(:hmac, sha_alg, secret, message)}
    end
  end

  defp sign_message(message, "ES" <> sha_bit_size, private_key) do
    # Per https://tools.ietf.org/html/rfc7515#appendix-A.3.1

    with {:ok, sha_alg} <- sha2_alg(sha_bit_size),
         {:ok, key}     <- decode_pem(private_key),
         der_signature  <- :public_key.sign(message, sha_alg, key) do

      {:'ECDSA-Sig-Value', r, s} = :public_key.der_decode(:'ECDSA-Sig-Value', der_signature)

      r_bin = sha_bit_pad(int_to_bin(r), sha_bit_size)
      s_bin = sha_bit_pad(int_to_bin(s), sha_bit_size)

      {:ok, r_bin <> s_bin}
    end
  end
  defp sign_message(message, <<_, "S", sha_bit_size :: binary>>, private_key) do
    with {:ok, sha_alg} <- sha2_alg(sha_bit_size),
         {:ok, key}     <- decode_pem(private_key) do

      {:ok, :public_key.sign(message, sha_alg, key)}
    end
  end
  defp sign_message(_message, alg, _jwk), do: {:error, "Unsupported JWT alg #{alg} or invalid JWK"}

  defp sha2_alg("256"), do: {:ok, :sha256}
  defp sha2_alg("384"), do: {:ok, :sha384}
  defp sha2_alg("512"), do: {:ok, :sha512}
  defp sha2_alg(bit_size), do: {:error, "Invalid SHA-2 algorithm bit size: #{bit_size}"}

  defp decode_pem(pem) do
    case :public_key.pem_decode(pem) do
      [entry] -> {:ok, :public_key.pem_entry_decode(entry)}
      _any    -> {:error, "Private key should only have one entry"}
    end
  end

  # From erlang crypto lib
  defp int_to_bin(x) when x < 0, do: int_to_bin_neg(x, [])
  defp int_to_bin(x), do: int_to_bin_pos(x, [])

  defp int_to_bin_pos(0, [_ | _] = ds), do: :erlang.list_to_binary(ds)
  defp int_to_bin_pos(x, ds), do: int_to_bin_pos(:erlang.bsr(x, 8), [:erlang.band(x, 255) | ds])

  defp int_to_bin_neg(-1, [msb | _] = ds) when msb >= 128, do: :erlang.list_to_binary(ds)
  defp int_to_bin_neg(x, ds), do: int_to_bin_neg(:erlang.bsr(x, 8), [:erlang.band(x, 255) | ds])

  defp sha_bit_pad(binary, "256"), do: lpad_binary(binary, byte_size(binary) - 32)
  defp sha_bit_pad(binary, "384"), do: lpad_binary(binary, byte_size(binary) - 48)
  defp sha_bit_pad(binary, "512"), do: lpad_binary(binary, byte_size(binary) - 66)

  defp lpad_binary(binary, length) when length > 0 do
    :binary.copy(<<0>>, length - byte_size(binary)) <> binary
  end
  defp lpad_binary(binary, _length), do: binary

  @impl JWTAdapter
  def verify(token, secret_or_public_key, opts) do
    with {:ok, encoded_jwt}              <- split(token),
         {:ok, %{"alg" => alg} = header} <- decode_base64_json(encoded_jwt.header, opts),
         {:ok, claims}                   <- decode_base64_json(encoded_jwt.claims, opts),
         {:ok, signature}                <- Base.url_decode64(encoded_jwt.signature, padding: false) do

      verified = verify_message("#{encoded_jwt.header}.#{encoded_jwt.claims}", signature, alg, secret_or_public_key)

      {:ok, %{
        header: header,
        claims: claims,
        signature: signature,
        verified?: verified
      }}
    end
  end

  defp split(token) do
    case String.split(token, ".") do
      [header, claims, signature] -> {:ok, %{header: header, claims: claims, signature: signature}}
      _any                        -> {:error, "Invalid JWT"}
    end
  end

  defp decode_base64_json(encoded, opts) do
    with {:ok, json_library} <- Config.fetch(opts, :json_library),
         {:ok, json}         <- Base.url_decode64(encoded, padding: false) do
      json_library.decode(json)
    end
  end

  defp verify_message(_message, _signature, "none", _secret), do: false
  defp verify_message(_message, _signature, _alg, nil), do: false
  defp verify_message(message, signature, "HS" <> _rest = alg, secret) when is_binary(secret) do
    case sign_message(message, alg, secret) do
      {:ok, signature_2} -> Assent.constant_time_compare(signature_2, signature)
      _any               -> false
    end
  end
  defp verify_message(message, signature, "ES" <> sha_bit_size, public_key) do
    with {:ok, sha_alg} <- sha2_alg(sha_bit_size),
         {:ok, pem}     <- decode_key(public_key) do

      # Per https://tools.ietf.org/html/rfc7515#appendix-A.3.1

      size           = :erlang.byte_size(signature)
      {r_bin, s_bin} = :erlang.split_binary(signature, Integer.floor_div(size, 2))
      r              = :crypto.bytes_to_integer(r_bin)
      s              = :crypto.bytes_to_integer(s_bin)
      der_signature  = :public_key.der_encode(:'ECDSA-Sig-Value', {:'ECDSA-Sig-Value', r, s})

      :public_key.verify(message, sha_alg, der_signature, pem)
    end
  end
  defp verify_message(message, signature, <<_, "S", sha_bit_size :: binary>>, public_key) do
    with {:ok, sha_alg} <- sha2_alg(sha_bit_size),
         {:ok, pem}     <- decode_key(public_key) do
      :public_key.verify(message, sha_alg, signature, pem)
    end
  end

  defp decode_key(pem) when is_binary(pem), do: decode_pem(pem)
  defp decode_key(%{"kty" => "RSA", "n" => n, "e" => e}) do
    with {:ok, n} <- Base.url_decode64(n, padding: false),
         {:ok, e} <- Base.url_decode64(e, padding: false) do
      {:ok, {:RSAPublicKey, :crypto.bytes_to_integer(n), :crypto.bytes_to_integer(e)}}
    end
  end
  defp decode_key(jwk) when is_map(jwk), do: {:error, "Can't decode JWK"}
end
