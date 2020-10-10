defmodule Assent.HTTPAdapter.HttpcTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Httpc

  alias ExUnit.CaptureIO
  alias Assent.HTTPAdapter.{Httpc, HTTPResponse}

  @expired_certificate_url "https://expired.badssl.com"
  @hsts_certificate_url "https://hsts.badssl.com"
  @unreachable_http_url "http://localhost:8888/"

  describe "request/4" do
    test "handles SSL" do
      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, @hsts_certificate_url, nil, [])
      assert {:error, {:failed_connect, error}} = Httpc.request(:get, @expired_certificate_url, nil, [])
      assert expired?(fetch_inet_error(error))

      assert CaptureIO.capture_io(:stderr, fn ->
        assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, @expired_certificate_url, nil, [], ssl: [])
      end) =~ "This request will NOT be verified for valid SSL certificate"

      assert {:error, {:failed_connect, error}} = Httpc.request(:get, @unreachable_http_url, nil, [])
      assert fetch_inet_error(error) == :econnrefused
    end

    test "handles query in URL" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/get", fn conn ->
        assert conn.query_string == "a=1"

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, "http://localhost:#{bypass.port}/get?a=1", nil, [])
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

      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:post, "http://localhost:#{bypass.port}/post", "a=1&b=2", [{"content-type", "application/x-www-form-urlencoded"}])
    end
  end

  defp fetch_inet_error([_, {:inet, [:inet], error}]), do: error

  defp expired?({:tls_alert, 'certificate expired'}), do: true # for :ssl < 9.2
  defp expired?({:tls_alert, {:certificate_expired, _error}}), do: true
  defp expired?(_any), do: false
  end
