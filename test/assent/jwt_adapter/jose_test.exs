defmodule Assent.JWTAdapter.JOSETest do
  use ExUnit.Case
  doctest Assent.JWTAdapter.JOSE

  alias Assent.JWTAdapter.{JOSE, JWT}

  @jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8"
  @payload %{"iat" => 1_516_239_022, "name" => "John Doe", "sub" => "1234567890"}

  test "decode/2" do
    assert {:ok, %JWT{header: header, payload: payload}} = JOSE.decode(@jwt, [json_library: Jason])
    assert is_nil(header)
    assert payload == @payload
  end
end
