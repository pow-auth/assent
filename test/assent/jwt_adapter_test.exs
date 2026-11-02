defmodule Assent.JWTAdapterTest do
  use ExUnit.Case
  doctest Assent.JWTAdapter

  alias Assent.JWTAdapter

  defmodule CustomJWTAdapter do
    @moduledoc false

    def sign(_claims, _alg, _secret, _opts), do: :signed

    def verify(_binary, _secret, _opts), do: :verified
  end

  defmodule CustomJSONLibrary do
    @moduledoc false

    def decode(_binary), do: {:ok, %{"alg" => "none", "custom_json" => true}}

    def encode!(_any), do: ""
  end

  @claims %{"iat" => 1_516_239_022, "name" => "John Doe", "sub" => "1234567890"}
  @alg "HS256"
  @secret "your-256-bit-secret"
  @token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8"

  @empty_encoding Base.url_encode64("", padding: false)

  test "sign/2" do
    assert JWTAdapter.sign(@claims, @alg, @secret, []) == {:ok, @token}

    assert JWTAdapter.sign(@token, @alg, @secret, jwt_adapter: CustomJWTAdapter) == :signed

    assert {:ok, @empty_encoding <> "." <> _rest} =
             JWTAdapter.sign(@token, @alg, @secret, json_library: CustomJSONLibrary)
  end

  test "verify/2" do
    assert {:ok, jwt} = JWTAdapter.verify(@token, @secret, [])
    assert jwt.verified?
    assert JWTAdapter.verify(@token, @secret, jwt_adapter: CustomJWTAdapter) == :verified

    assert {:ok, %{header: %{"custom_json" => true}}} =
             JWTAdapter.verify(@token, @secret, json_library: CustomJSONLibrary)
  end

  test "decode_pem/1" do
    key = :public_key.generate_key({:rsa, 1024, 65_537})
    entry = :public_key.pem_entry_encode(elem(key, 0), key)
    pem = :public_key.pem_encode([entry])

    assert {:ok, decoded_key} = JWTAdapter.decode_pem(pem)
    assert decoded_key == :public_key.pem_entry_decode(entry)

    assert {:error, %ArgumentError{message: "expected one PEM entry, got none"}} =
             JWTAdapter.decode_pem("invalid")

    assert {:error, %ArgumentError{message: "expected one PEM entry, got 2"}} =
             JWTAdapter.decode_pem(pem <> pem)
  end

  @tag :tmp_dir
  test "load_private_key/1", %{tmp_dir: tmp_dir} do
    missing_private_key_path = Path.join(tmp_dir, "missing.pem")
    private_key_path = Path.join(tmp_dir, "private-key.pem")
    :ok = File.write!(private_key_path, "private_key")

    assert {:error, %Assent.MissingConfigError{} = error} = JWTAdapter.load_private_key([])
    assert error.key == :private_key

    assert JWTAdapter.load_private_key(private_key: "private_key") == {:ok, "private_key"}

    assert {:error, %File.Error{} = error} =
             JWTAdapter.load_private_key(private_key_path: missing_private_key_path)

    assert error.path == missing_private_key_path
    assert error.reason == :enoent

    assert JWTAdapter.load_private_key(private_key_path: private_key_path) ==
             {:ok, "private_key"}
  end
end
