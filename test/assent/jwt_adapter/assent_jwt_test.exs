defmodule Assent.JWTAdapter.AssentJWTTest do
  use ExUnit.Case
  doctest Assent.JWTAdapter.AssentJWT

  alias Assent.JWTAdapter.{AssentJWT, JWT}

  @jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8"
  @header %{"alg" => "HS256", "typ" => "JWT"}
  @payload %{"iat" => 1_516_239_022, "name" => "John Doe", "sub" => "1234567890"}

  test "decode/2" do
    assert {:ok, %JWT{header: header, payload: payload}} = AssentJWT.decode(@jwt, [json_library: Jason])
    assert header == @header
    assert payload == @payload
  end
end
