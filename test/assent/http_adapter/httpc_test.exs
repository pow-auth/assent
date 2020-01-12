defmodule Assent.HTTPAdapter.HttpcTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Httpc

  alias Assent.HTTPAdapter.{Httpc, HTTPResponse}

  @expired_certificate_url "https://expired.badssl.com"
  @hsts_certificate_url "https://hsts.badssl.com"
  @unreachable_http_url "http://localhost:8888/"

  @expired_certificate_errors [{:tls_alert, 'certificate expired'}, {:tls_alert, {:certificate_expired, 'received CLIENT ALERT: Fatal - Certificate Expired'}}]  # :ssl 9.2 changes the tls alert error format so we test for both versions
  @unreachable_http_error :econnrefused

  describe "request/4" do
    test "handles SSL" do
      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, @hsts_certificate_url, nil, [])
      assert {:error, {:failed_connect, error}} = Httpc.request(:get, @expired_certificate_url, nil, [])
      assert fetch_inet_error(error) in @expired_certificate_errors

      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, @expired_certificate_url, nil, [], ssl: [])

      assert {:error, {:failed_connect, error}} = Httpc.request(:get, @unreachable_http_url, nil, [])
      assert fetch_inet_error(error) == @unreachable_http_error
    end

    test "handles query in URL" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/get", fn conn ->
        assert conn.query_string == "a=1"

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Httpc.request(:get, "http://localhost:#{bypass.port}/get?a=1", nil, [])
    end
  end

  defp fetch_inet_error([_, {:inet, [:inet], error}]), do: error
end
