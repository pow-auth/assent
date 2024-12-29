defmodule Assent.JWTAdapterTest do
  use Assent.TestCase
  doctest Assent.Strategy

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

  test "load_private_key/1" do
    assert {:error, %Assent.Config.MissingKeyError{} = error} = JWTAdapter.load_private_key([])
    assert error.key == :private_key

    assert JWTAdapter.load_private_key(private_key: "private_key") == {:ok, "private_key"}

    assert JWTAdapter.load_private_key(private_key_path: "tmp/invalid.pem") ==
             {:error, "Failed to read \"tmp/invalid.pem\", got; :enoent"}

    File.mkdir_p!("tmp/")
    File.write!("tmp/private-key.pem", "private_key")

    assert JWTAdapter.load_private_key(private_key_path: "tmp/private-key.pem") ==
             {:ok, "private_key"}
  end
end
