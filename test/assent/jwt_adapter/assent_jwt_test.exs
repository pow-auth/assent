defmodule Assent.JWTAdapter.AssentJWTTest do
  use Assent.TestCase
  doctest Assent.JWTAdapter.AssentJWT

  alias Assent.JWTAdapter.AssentJWT

  @token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8"
  @header %{}
  @claims %{"iat" => 1_516_239_022, "name" => "John Doe", "sub" => "1234567890"}
  @secret "your-256-bit-secret"

  test "sign/2" do
    assert AssentJWT.sign(@claims, "HS256", @secret, json_library: @json_library) == {:ok, @token}
  end

  test "sign/2 with invalid header" do
    unencodable = & &1

    assert {:error, error} =
             AssentJWT.sign(@claims, "HS256", @secret,
               json_library: @json_library,
               private_key_id: unencodable
             )

    assert error.message == "Failed to encode header"
    assert %Protocol.UndefinedError{} = error.reason
    assert %{"typ" => "JWT", "alg" => "HS256", "kid" => _} = error.data
  end

  test "sign/2 with invalid claims" do
    unencodable = & &1

    assert {:error, error} =
             AssentJWT.sign(unencodable, "HS256", @secret, json_library: @json_library)

    assert error.message == "Failed to encode claims"
    assert %Protocol.UndefinedError{} = error.reason
    assert error.data == unencodable
  end

  test "sign/2 with invalid algorithm" do
    assert {:error, error} = AssentJWT.sign(@claims, "none", @secret, json_library: @json_library)
    assert error.message == "Failed to sign JWT"
    assert error.reason == "Unsupported JWT alg none or invalid JWK"
    assert {_, "none"} = error.data

    assert {:error, error} =
             AssentJWT.sign(@claims, "HS000", @secret, json_library: @json_library)

    assert error.message == "Failed to sign JWT"
    assert error.reason == "Invalid SHA-2 algorithm bit size: 000"
    assert {_, "HS000"} = error.data
  end

  test "verify/3" do
    assert {:ok, jwt} = AssentJWT.verify(@token, "invalid", json_library: @json_library)
    refute jwt.verified?
    assert jwt.claims == @claims

    assert {:ok, jwt} = AssentJWT.verify(@token, @secret, json_library: @json_library)
    assert jwt.verified?
    assert jwt.claims == @claims
  end

  test "verify/3 with invalid JWT format" do
    too_long = @token <> ".value"

    assert {:error, error} = AssentJWT.verify(too_long, @secret, json_library: @json_library)
    assert error.message == "JWT must have exactly three parts"
    assert error.reason == :invalid_format
    assert [_, _, _, "value"] = error.data

    too_short = @token |> String.split(".") |> Enum.take(2) |> Enum.join(".")

    assert {:error, error} = AssentJWT.verify(too_short, @secret, json_library: @json_library)
    assert error.message == "JWT must have exactly three parts"
    assert error.reason == :invalid_format
    assert [_, _] = error.data
  end

  @invalid_base64 "@invalid-header"
  test "verify/3 with header with invalid base64" do
    token = replace_jwt_at(@token, 0, @invalid_base64)

    assert {:error, error} = AssentJWT.verify(token, @secret, json_library: @json_library)
    assert error.message == "Failed to decode header"
    assert error.reason == "Invalid Base64URL"
    assert error.data == @invalid_base64
  end

  defp replace_jwt_at(jwt, position, value) do
    jwt
    |> String.split(".")
    |> List.replace_at(position, value)
    |> Enum.join(".")
  end

  @invalid_json Base.url_encode64("%{invalid-header}", padding: false)
  test "verify/3 with header with invalid json" do
    token = replace_jwt_at(@token, 0, @invalid_json)

    assert {:error, error} = AssentJWT.verify(token, @secret, json_library: @json_library)
    assert error.message == "Failed to decode header"

    if unquote(@json_library == Jason) do
      assert %Jason.DecodeError{} = error.reason
    else
      assert error.reason == {:invalid_byte, 0, 37}
    end

    assert error.data == @invalid_json
  end

  @header Base.url_encode64(@json_library.encode!(%{}), padding: false)
  test "verify/3 with header with missing \"alg\"" do
    token = replace_jwt_at(@token, 0, @header)

    assert {:error, error} = AssentJWT.verify(token, @secret, json_library: @json_library)
    assert error.message == "Failed to decode header"
    assert error.reason == "No \"alg\" found in header"
    assert error.data == @header
  end

  @invalid_base64 "@invalid-claims"
  test "verify/3 with claims with invalid base64" do
    token = replace_jwt_at(@token, 1, @invalid_base64)

    assert {:error, error} = AssentJWT.verify(token, @secret, json_library: @json_library)
    assert error.message == "Failed to decode claims"
    assert error.reason == "Invalid Base64URL"
    assert error.data == @invalid_base64
  end

  @invalid_json Base.url_encode64("%{invalid-claims}", padding: false)
  test "verify/3 with claims with invalid json" do
    token = replace_jwt_at(@token, 1, @invalid_json)

    assert {:error, error} = AssentJWT.verify(token, @secret, json_library: @json_library)
    assert error.message == "Failed to decode claims"

    if unquote(@json_library == Jason) do
      assert %Jason.DecodeError{} = error.reason
    else
      assert error.reason == {:invalid_byte, 0, 37}
    end

    assert error.data == @invalid_json
  end

  @invalid_base64 "@invalid-signature"
  test "verify/3 with signature with invalid base64" do
    token = replace_jwt_at(@token, 2, @invalid_base64)

    assert {:error, error} = AssentJWT.verify(token, @secret, json_library: @json_library)
    assert error.message == "Failed to decode signature"
    assert error.reason == "Invalid Base64URL"
    assert error.data == @invalid_base64
  end

  test "verify/3 with no secret" do
    assert {:ok, jwt} = AssentJWT.verify(@token, nil, json_library: @json_library)
    refute jwt.verified?
  end

  describe "with private key" do
    @token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.Skbmm3dBBdPCt0T1dqgtIYW_xbsmlOMJxC6g4WEgWRbk21tw2r2erDBwPxap4Z1rszWnFrmbULm83YSH-1pcHZ-mdNSqFp4_0mtIR3wHvshLSBhxL_3nuwV0hRYUqjjWOZRsBiZEHi9aZMVTm4dWsQlTJAHqQV1igwayn59d0TKmLSgDMvKxQU59SjBeXjVVia05IK7h6zJQ5GmjpzQmbOVpgig3_fxsuDP5-DXyteXKkLbLU23L_K2Pr8FgiJ_KlG2JpIoUB3DcR_tm-vmtUv-dB6ndqPC4RFgzt_4MCzZdzf-9cE5v0XwDxvKpNvZk-UOvTn6bqFdIChJ_1s8WaA"
    @private_key """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
    kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
    m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
    NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
    3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
    QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
    kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
    amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
    +bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
    D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
    0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
    lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
    hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
    bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
    +jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
    BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
    2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
    QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
    5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
    Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
    NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
    8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
    3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
    y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
    jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
    -----END RSA PRIVATE KEY-----
    """
    @public_key """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
    vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
    aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
    tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
    e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
    V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
    MwIDAQAB
    -----END PUBLIC KEY-----
    """

    test "sign/2" do
      assert AssentJWT.sign(@claims, "RS256", @private_key, json_library: @json_library) ==
               {:ok, @token}

      refute AssentJWT.sign(@claims, "RS256", @private_key,
               json_library: @json_library,
               private_key_id: "key_id"
             ) == {:ok, @token}
    end

    test "sign/2 with invalid algorithm" do
      assert {:error, error} =
               AssentJWT.sign(@claims, "RS000", @private_key, json_library: @json_library)

      assert error.message == "Failed to sign JWT"
      assert error.reason == "Invalid SHA-2 algorithm bit size: 000"
      assert {_, "RS000"} = error.data
    end

    test "sign/2 with invalid pem" do
      assert {:error, error} =
               AssentJWT.sign(@claims, "RS256", "invalid", json_library: @json_library)

      assert error.message == "Failed to sign JWT"
      assert error.reason == "Invalid private key"

      assert {:error, error} =
               AssentJWT.sign(@claims, "RS256", @private_key <> @private_key,
                 json_library: @json_library
               )

      assert error.message == "Failed to sign JWT"
      assert error.reason == "Private key should only have one entry"
    end

    test "verify/3" do
      assert {:ok, jwt} = AssentJWT.verify(@token, @public_key, json_library: @json_library)
      assert jwt.verified?
      assert jwt.claims == @claims
    end

    @jwk %{
      "e" => "AQAB",
      "kty" => "RSA",
      "n" =>
        "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw"
    }

    test "verify/3 with JWK" do
      assert {:ok, jwt} = AssentJWT.verify(@token, @jwk, json_library: @json_library)
      assert jwt.verified?
      assert jwt.claims == @claims
    end

    test "verify/3 with nil secret" do
      assert {:ok, jwt} = AssentJWT.verify(@token, nil, json_library: @json_library)
      refute jwt.verified?
      assert jwt.claims == @claims
    end
  end

  if :crypto.supports()[:curves] do
    describe "with private key using ES256" do
      @token "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
      @private_key """
      -----BEGIN PRIVATE KEY-----
      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
      OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
      1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
      -----END PRIVATE KEY-----
      """
      @public_key """
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
      q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
      -----END PUBLIC KEY-----
      """
      @claims %{
        "sub" => "1234567890",
        "name" => "John Doe",
        "admin" => true,
        "iat" => 1_516_239_022
      }

      test "signs and verifies" do
        assert {:ok, token} =
                 AssentJWT.sign(@claims, "ES256", @private_key, json_library: @json_library)

        assert {:ok, jwt} = AssentJWT.verify(token, @public_key, json_library: @json_library)
        assert jwt.verified?

        assert {:ok, jwt} = AssentJWT.verify(@token, @public_key, json_library: @json_library)
        assert jwt.verified?
      end

      test "sign/2 with invalid algorithm" do
        assert {:error, error} =
                 AssentJWT.sign(@claims, "ES000", @private_key, json_library: @json_library)

        assert error.message == "Failed to sign JWT"
        assert error.reason == "Invalid SHA-2 algorithm bit size: 000"
        assert {_, "ES000"} = error.data
      end

      test "sign/2 with invalid pem" do
        assert {:error, error} =
                 AssentJWT.sign(@claims, "ES256", "invalid", json_library: @json_library)

        assert error.message == "Failed to sign JWT"
        assert error.reason == "Invalid private key"

        assert {:error, error} =
                 AssentJWT.sign(@claims, "ES256", @private_key <> @private_key,
                   json_library: @json_library
                 )

        assert error.message == "Failed to sign JWT"
        assert error.reason == "Private key should only have one entry"
      end
    end
  end
end
