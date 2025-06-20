defmodule Assent.StrategyTest do
  use Assent.TestCase
  doctest Assent.Strategy

  alias Assent.Strategy

  test "http_request/5 with `prepare_http_request: {module, function, arguments}` with invalid return" do
    config = [
      prepare_http_request: {__MODULE__, :invalid_prepare_http_request_return, []}
    ]

    assert_raise ArgumentError,
                 "expected #{inspect(__MODULE__)}.invalid_prepare_http_request_return/1 to return an Assent.HTTPAdapter.HTTPRequest struct",
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

    @invalid_user %{
      "sub" => true,
      "address" => %{
        "formatted" => true
      }
    }

    @expected_user %{
      "sub" => "123",
      "email" => "foo@example.com",
      "email_verified" => true,
      "address" => %{
        "formatted" => "456"
      },
      "updated_at" => 1_516_239_022
    }

    test "with incorrect claim type" do
      assert {:error, %Assent.CastClaimsError{} = error} =
               Strategy.normalize_userinfo(@invalid_user, %{})

      assert Exception.message(error) == """
             The following claims couldn't be cast:

             - "address" -> "formatted" to :binary
             - "sub" to :binary
             """
    end

    test "with atom value claim" do
      user = %{"sub" => :invalid}

      assert {:error, %Assent.CastClaimsError{} = error} = Strategy.normalize_userinfo(user, %{})
      assert error.invalid_types == %{"sub" => :binary}
    end

    test "with binary type claim with integer value" do
      user = %{"sub" => 123}

      assert {:ok, %{"sub" => "123"}} = Strategy.normalize_userinfo(user, %{})
    end

    test "with integer type claim with invalid binary value" do
      user = %{"updated_at" => "123a1"}

      assert {:error, %Assent.CastClaimsError{} = error} = Strategy.normalize_userinfo(user, %{})
      assert error.invalid_types == %{"updated_at" => :integer}
    end

    test "with integer type claim with valid binary value" do
      user = %{"updated_at" => "123"}

      assert {:ok, %{"updated_at" => 123}} = Strategy.normalize_userinfo(user, %{})
    end

    test "with boolean type claim with string binary value" do
      user = %{"email_verified" => "true"}

      assert {:ok, %{"email_verified" => true}} = Strategy.normalize_userinfo(user, %{})

      user = %{"email_verified" => "false"}

      assert {:ok, %{"email_verified" => false}} = Strategy.normalize_userinfo(user, %{})
    end

    test "casts" do
      assert Strategy.normalize_userinfo(@valid_user) == {:ok, @expected_user}
    end

    test "with unknown claims" do
      user =
        @valid_user
        |> Map.put("foo", "bar")
        |> Map.put("address", Map.put(@valid_user["address"], "foo", "bar"))

      assert Strategy.normalize_userinfo(user) == {:ok, @expected_user}
    end

    test "with extra" do
      extra =
        %{
          "a" => 1,
          "b" => nil,
          "sub" => "other-sub",
          "address" => %{
            "formatted" => "other-foramtted",
            "a" => nil,
            "b" => 2
          }
        }

      expected_user =
        @expected_user
        |> Map.put("a", 1)
        |> Map.put("address", Map.put(@expected_user["address"], "b", 2))

      assert Strategy.normalize_userinfo(@valid_user, extra) == {:ok, expected_user}
    end
  end
end
