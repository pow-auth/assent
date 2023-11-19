defmodule Assent.JWTAdapter.JOSE do
  @moduledoc """
  JWT adapter module for parsing JSON Web Tokens with JOSE.

  You can append options to the configuration:

      jwt_adapter: {Assent.JWTAdapter.JOSE, [...]}

  See `Assent.JWTAdapter` for more.
  """
  alias Assent.JWTAdapter

  @behaviour Assent.JWTAdapter

  @impl JWTAdapter
  def sign(claims, alg, secret, opts) do
    jwk = jwk(alg, secret)
    jws = jws(alg, opts)

    {_, token} =
      jwk
      |> JOSE.JWT.sign(jws, claims)
      |> JOSE.JWS.compact()

    {:ok, token}
  end

  defp jwk("HS" <> _rest, secret), do: JOSE.JWK.from_oct(secret)
  defp jwk(_alg, key) when is_binary(key), do: JOSE.JWK.from_pem(key)
  defp jwk(_alg, key) when is_map(key), do: JOSE.JWK.from_map(key)

  defp jws(alg, opts) do
    jws = %{"alg" => alg}

    case Keyword.get(opts, :private_key_id) do
      nil -> jws
      kid -> Map.put(jws, "kid", kid)
    end
  end

  @impl JWTAdapter
  def verify(token, secret_or_public_key, _opts) do
    {_, %{"alg" => alg} = header} =
      token
      |> JOSE.JWT.peek_protected()
      |> JOSE.JWS.to_map()

    {verified, %{fields: claims}} = verify_message(token, alg, secret_or_public_key)

    {%{}, %{"signature" => signature}} = JOSE.JWS.expand(token)

    {:ok,
     %{
       header: header,
       claims: claims,
       signature: signature,
       verified?: verified
     }}
  end

  defp verify_message(token, _alg, nil) do
    {false, JOSE.JWT.peek_payload(token)}
  end

  defp verify_message(token, alg, secret_or_public_key) do
    {verified, payload, _} =
      alg
      |> jwk(secret_or_public_key)
      |> JOSE.JWT.verify(token)

    {verified, payload}
  end
end
