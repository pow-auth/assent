defmodule Assent.StrategyTest do
  use ExUnit.Case
  doctest Assent.Strategy

  alias Assent.Strategy

  test "http_request/5 with `prepare_http_request: {module, function, arguments}` with invalid return" do
    config = [
      prepare_http_request: {__MODULE__, :invalid_prepare_http_request_return, []}
    ]

    assert_raise ArgumentError,
                 "expected #{inspect(__MODULE__)}.invalid_prepare_http_request_return/1 to return %Assent.HTTPAdapter.HTTPRequest{}",
                 fn ->
                   Strategy.http_request(:get, "http://example.com/", nil, [], config)
                 end
  end

  def invalid_prepare_http_request_return(_request), do: :invalid

  test "http_request/5 with `prepare_http_request: {module, function, arguments}`" do
    TestServer.add("/path",
      via: :get,
      to: fn conn ->
        assert Plug.Conn.get_req_header(conn, "x-api-version") == ["1"]

        Plug.Conn.send_resp(conn, 200, "")
      end
    )

    config = [
      prepare_http_request: {__MODULE__, :put_header, ["x-api-version", "1"]}
    ]

    assert {:ok, _response} =
             Strategy.http_request(:get, TestServer.url("/path"), nil, [], config)
  end

  def put_header(request, key, value) do
    %{request | headers: [{key, value} | request.headers]}
  end

  test "to_url/3" do
    assert Strategy.to_url("http://example.com", "/path") == "http://example.com/path"
    assert Strategy.to_url("http://example.com/", "/path") == "http://example.com/path"

    assert Strategy.to_url("http://example.com/path", "/other-path") ==
             "http://example.com/path/other-path"

    assert Strategy.to_url("http://example.com/path/", "/other-path") ==
             "http://example.com/path/other-path"

    assert Strategy.to_url("http://example.com/path", "http://example.org/other-path") ==
             "http://example.org/other-path"

    assert Strategy.to_url("http://example.com", "/path", a: 1, b: [c: 2, d: [e: 3]], f: [4, 5]) ==
             "http://example.com/path?a=1&b[c]=2&b[d][e]=3&f[]=4&f[]=5"
  end

  describe "normalize_userinfo/2" do
    @valid_user %{
      "sub" => "123",
      "email" => "foo@example.com",
      "email_verified" => true,
      "address" => %{
        "formatted" => "456"
      },
      "updated_at" => 1_516_239_022
    }

    @extra %{
      "a" => 1,
      "b" => nil,
      "sub" => "other-sub",
      "address" => %{
        "formatted" => "other-formatted",
        "a" => nil,
        "b" => 2
      }
    }

    @invalid_user %{
      "sub" => true,
      "address" => %{
        "formatted" => true
      }
    }

    test "with invalid claims" do
      assert {:error, %Assent.CastClaimsError{}} =
               Strategy.normalize_userinfo(@invalid_user, @extra)
    end

    test "with valid claims" do
      expected_user =
        @valid_user
        |> Map.put("a", 1)
        |> Map.put("address", Map.put(@valid_user["address"], "b", 2))

      assert Strategy.normalize_userinfo(@valid_user, @extra) == {:ok, expected_user}
    end
  end

  describe "cast_claims/2" do
    test "with invalid claims" do
      claims = %{
        "binary" => :invalid,
        "integer" => "invalid",
        "boolean" => "invalid",
        "map" => "invalid",
        "nested" => %{"binary" => :invalid}
      }

      claim_types = %{
        "binary" => :binary,
        "integer" => :integer,
        "boolean" => :boolean,
        "map" => %{"binary" => :binary},
        "nested" => %{"binary" => :binary}
      }

      assert {:error, %Assent.CastClaimsError{} = error} =
               Strategy.cast_claims(claims, claim_types)

      assert error.claims == claims
      assert error.invalid_types == %{claim_types | "map" => :map}
    end

    test "with unrelated claims" do
      assert Strategy.cast_claims(%{}, %{"boolean" => :boolean}) == {:ok, %{}}

      assert Strategy.cast_claims(%{"other" => "value"}, %{"key" => :boolean}) ==
               {:ok, %{}}
    end

    test "with valid claims" do
      claims = %{
        "binary" => 123,
        "integer" => "456",
        "boolean_true" => "true",
        "boolean_false" => "false",
        "nested" => %{"binary" => 789, "unknown" => "value"},
        "unknown" => "value"
      }

      claim_types = %{
        "binary" => :binary,
        "integer" => :integer,
        "boolean_true" => :boolean,
        "boolean_false" => :boolean,
        "nested" => %{"binary" => :binary}
      }

      assert Strategy.cast_claims(claims, claim_types) ==
               {:ok,
                %{
                  "binary" => "123",
                  "integer" => 456,
                  "boolean_true" => true,
                  "boolean_false" => false,
                  "nested" => %{"binary" => "789"}
                }}
    end
  end
end
