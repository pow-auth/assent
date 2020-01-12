defmodule Assent.HTTPAdapter.MintTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Mint

  alias Mint.TransportError
  alias Assent.HTTPAdapter.{Mint, HTTPResponse}

  @expired_certificate_url "https://expired.badssl.com"
  @hsts_certificate_url "https://hsts.badssl.com"
  @unreachable_http_url "http://localhost:8888/"

  {otp_version, _} = Integer.parse(to_string(:erlang.system_info(:otp_release)))
  @certificate_expired_error if otp_version >= 22, do: {:tls_alert, {:certificate_expired, 'received CLIENT ALERT: Fatal - Certificate Expired'}}, else: {:tls_alert, 'certificate expired'}

  describe "request/4" do
    test "handles SSL" do
      assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, @hsts_certificate_url, nil, [])
      assert {:error, %TransportError{reason: @certificate_expired_error}} = Mint.request(:get, @expired_certificate_url, nil, [])

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
  end
end
