defmodule Assent.HTTPAdapter.HttpcTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Httpc

  alias ExUnit.{CaptureIO, CaptureLog}
  alias Assent.HTTPAdapter.{Httpc, HTTPResponse}
  alias Assent.TestServer

  @wrong_host_certificate_url "https://wrong.host.badssl.com"
  @hsts_certificate_url "https://hsts.badssl.com"
  @unreachable_http_url "http://localhost:8888/"

  describe "request/4" do
    test "handles SSL" do
      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, @hsts_certificate_url, nil, [])
      assert {:error, {:failed_connect, error}} = Httpc.request(:get, @wrong_host_certificate_url, nil, [])
      assert {:tls_alert, {:handshake_failure, _error}} = fetch_inet_error(error)

      # For OTP 24 "Authenticity is not established by certificate path validation" warning
      CaptureLog.capture_log(fn ->
        assert CaptureIO.capture_io(:stderr, fn ->
          assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, @wrong_host_certificate_url, nil, [], ssl: [])
        end) =~ "This request will NOT be verified for valid SSL certificate"
      end)

      assert {:error, {:failed_connect, error}} = Httpc.request(:get, @unreachable_http_url, nil, [])
      assert fetch_inet_error(error) == :econnrefused
    end

    test "handles query in URL" do
      TestServer.expect("GET", "/get", fn conn ->
        assert conn.query_string == "a=1"

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, TestServer.url("/get?a=1"), nil, [])
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

      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:post, TestServer.url("/post"), "a=1&b=2", [{"content-type", "application/x-www-form-urlencoded"}])
    end
  end

  defp fetch_inet_error([_, {:inet, [:inet], error}]), do: error
end
