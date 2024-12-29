defmodule AssentTest do
  use Assent.TestCase
  doctest Assent

  test "fetch_config/2" do
    config = [a: 1, b: 2]

    assert Assent.fetch_config(config, :a) == {:ok, 1}

    assert {:error, %Assent.MissingConfigError{} = error} = Assent.fetch_config(config, :c)
    assert error.key == :c
    assert error.config == config
    assert Exception.message(error) == "Expected :c in config, got: [:a, :b]"
  end

  test "fetch_param/2" do
    params = %{"a" => 1, "b" => 2}

    assert Assent.fetch_param(params, "a") == {:ok, 1}

    assert {:error, %Assent.MissingParamError{} = error} = Assent.fetch_param(params, "c")
    assert error.expected_key == "c"
    assert error.params == params
    assert Exception.message(error) == "Expected \"c\" in params, got: [\"a\", \"b\"]"
  end
end
