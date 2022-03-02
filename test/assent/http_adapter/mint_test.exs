defmodule Assent.HTTPAdapter.MintTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Mint

  alias ExUnit.CaptureLog
  alias Mint.TransportError
  alias Assent.HTTPAdapter.{HTTPResponse, Mint}
  alias Assent.TestServer

  describe "request/4" do
    test "handles SSL" do
      TestServer.setup(scheme: :https)
      TestServer.expect("GET", "/")

      mint_opts = [transport_opts: [cacertfile: TestServer.cacertfile()], protocols: [:http1]]

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} = Mint.request(:get, TestServer.url(), nil, [], mint_opts)
    end

    test "handles SSL with bad certificate" do
      TestServer.setup(scheme: :https)
      TestServer.expect("GET", "/")

      mint_opts = [transport_opts: [cacertfile: TestServer.cacertfile()]]

      assert {:error, %TransportError{reason: {:tls_alert, {:handshake_failure, _error}}}} = Mint.request(:get, TestServer.url(domain: "bad-host.localhost"), nil, [], mint_opts)

      # For OTP 24 "Authenticity is not established by certificate path validation" warning
      CaptureLog.capture_log(fn ->
        mint_opts = put_in(mint_opts, [:transport_opts, :verify], :verify_none)

        assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, TestServer.url(), nil, [], mint_opts)
      end)
    end

    if :crypto.supports()[:curves] do
      test "handles http/2" do
        TestServer.setup(scheme: :https)
        TestServer.expect("GET", "/")

        mint_opts = [transport_opts: [cacertfile: TestServer.cacertfile()]]

        assert {:ok, %HTTPResponse{status: 200, body: "HTTP/2"}} = Mint.request(:get, TestServer.url(), nil, [], mint_opts)
      end
    else
      IO.warn("No support curve algorithms, can't test in #{__MODULE__}")
    end

    test "handles unreachable host" do
      TestServer.setup()
      TestServer.down()

      assert {:error, %TransportError{reason: :econnrefused}} = Mint.request(:get, TestServer.url(), nil, [])
    end

    test "handles query in URL" do
      TestServer.expect("GET", "/get", fn conn ->
        assert conn.query_string == "a=1"

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, TestServer.url("/get?a=1"), nil, [])
    end

    test "handles POST" do
      TestServer.expect("POST", "/post", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        assert params["a"] == "1"
        assert params["b"] == "2"
        assert Plug.Conn.get_req_header(conn, "content-type") == ["application/x-www-form-urlencoded"]

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:post, TestServer.url("/post"), "a=1&b=2", [{"content-type", "application/x-www-form-urlencoded"}])
    end
  end
end
