defmodule Assent.HTTPAdapter.MintTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Mint

  alias ExUnit.CaptureLog
  alias Mint.TransportError
  alias Assent.HTTPAdapter.{HTTPResponse, Mint}

  @wrong_host_certificate_url "https://wrong.host.badssl.com"
  @hsts_certificate_url "https://hsts.badssl.com"
  @unreachable_http_url "http://localhost:8888/"

  describe "request/4" do
    test "handles SSL" do
      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, @hsts_certificate_url, nil, [])
      assert {:error, %TransportError{reason: {:tls_alert, {:handshake_failure, _error}}}} = Mint.request(:get, @wrong_host_certificate_url, nil, [])

      # For OTP 24 "Authenticity is not established by certificate path validation" warning
      CaptureLog.capture_log(fn ->
        assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, @wrong_host_certificate_url, nil, [], transport_opts: [verify: :verify_none])
      end)

      assert {:error, %TransportError{reason: :econnrefused}} = Mint.request(:get, @unreachable_http_url, nil, [])
    end

    if :crypto.supports()[:curves] do
      test "handles http/2" do
        assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, "https://http2.golang.org/", nil, [])
      end
    else
      IO.warn("No support curve algorithms, can't test in #{__MODULE__}")
    end

    test "handles query in URL" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/get", fn conn ->
        assert conn.query_string == "a=1"

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, "http://localhost:#{bypass.port}/get?a=1", nil, [])
    end

    test "handles POST" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "POST", "/post", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        assert params["a"] == "1"
        assert params["b"] == "2"
        assert Plug.Conn.get_req_header(conn, "content-type") == ["application/x-www-form-urlencoded"]

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:post, "http://localhost:#{bypass.port}/post", "a=1&b=2", [{"content-type", "application/x-www-form-urlencoded"}])
    end
  end
end
