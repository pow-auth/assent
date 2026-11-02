defmodule AssentTest do
  use ExUnit.Case
  doctest Assent
  doctest Assent.MissingConfigError
  doctest Assent.CallbackCSRFError
  doctest Assent.MissingParamError
  doctest Assent.RequestError
  doctest Assent.ServerUnreachableError
  doctest Assent.CastClaimsError

  test "fetch_config/2" do
    config = [a: 1, b: 2]

    assert Assent.fetch_config(config, :a) == {:ok, 1}

    assert {:error, %Assent.MissingConfigError{} = error} = Assent.fetch_config(config, :c)
    assert error.key == :c
    assert error.config == config
  end

  test "fetch_param/2" do
    params = %{"a" => 1, "b" => 2}

    assert Assent.fetch_param(params, "a") == {:ok, 1}

    assert {:error, %Assent.MissingParamError{} = error} = Assent.fetch_param(params, "c")
    assert error.key == "c"
    assert error.params == params
  end

  test "fetch_token_param/2" do
    params = %{"a" => 1, "b" => 2}

    assert Assent.fetch_token_param(params, "a") == {:ok, 1}

    assert {:error, %Assent.MissingParamError{} = error} = Assent.fetch_token_param(params, "c")
    assert error.key == "c"
    assert error.params == params
  end
end
