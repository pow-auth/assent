defmodule Assent.JWTAdapter.JOSE do
  @moduledoc """
  JWT adapter module for parsing JWT tokens with JOSE.
  """
  alias Assent.{JWTAdapter, JWTAdapter.JWT}

  @behaviour Assent.JWTAdapter


  @impl JWTAdapter
  def sign(%JWT{header: header, payload: payload} = jwt, secret, _opts) do
    {_, token} =
      jwt
      |> jwk(secret)
      |> JOSE.JWT.sign(header, payload)
      |> JOSE.JWS.compact()

    {:ok, token}
  end

  defp jwk(%{header: %{"alg" => "HS" <> _rest}}, secret), do: JOSE.JWK.from_oct(secret)
  defp jwk(_jwt, secret), do: JOSE.JWK.from_pem(secret)

  @impl JWTAdapter
  def verify(jwt, secret, _opts) do
    {verified, _, _} =
      jwt
      |> jwk(secret)
      |> JOSE.JWT.verify(jwt.encoded[:jwt])

    verified
  end

  @impl JWTAdapter
  def decode(token, json_library: json_library) do
    JOSE.json_module(json_library)

    header_json  = JOSE.JWS.peek_protected(token)
    payload_json = JOSE.JWS.peek_payload(token)
    signature    = JOSE.JWS.peek_signature(token)

    with {:ok, header}  <- json_library.decode(header_json),
         {:ok, payload} <- json_library.decode(payload_json) do
      {:ok, %JWT{
        header: header,
        payload: payload,
        encoded: %{
          header: header_json,
          payload: payload_json,
          signature: signature,
          jwt: token
        }
      }}
    end
  end
end
