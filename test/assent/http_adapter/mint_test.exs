defmodule Assent.HTTPAdapter.MintTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Mint

  alias Mint.TransportError
  alias Assent.HTTPAdapter.{HTTPResponse, Mint}

  @expired_certificate_url "https://expired.badssl.com"
  @hsts_certificate_url "https://hsts.badssl.com"
  @unreachable_http_url "http://localhost:8888/"

  describe "request/4" do
    test "handles SSL" do
      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, @hsts_certificate_url, nil, [])
      assert {:error, %TransportError{reason: error}} = Mint.request(:get, @expired_certificate_url, nil, [])
      assert expired?(error)

      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, @expired_certificate_url, nil, [], transport_opts: [verify: :verify_none])

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

  defp expired?({:tls_alert, {:certificate_expired, _error}}), do: true
  defp expired?({:tls_alert, 'certificate expired'}), do: true # For OTP version < 22
  defp expired?(_any), do: false
end
