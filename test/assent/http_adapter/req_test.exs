defmodule Assent.HTTPAdapter.ReqTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Req

  alias Mint.TransportError
  alias Assent.HTTPAdapter.{HTTPResponse, Req}

  describe "request/4" do
    test "handles SSL" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      req_opts = [connect_options: [transport_opts: [cacerts: TestServer.x509_suite().cacerts]]]

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} = Req.request(:get, TestServer.url(), nil, [], req_opts)
    end

    test "handles SSL with bad certificate" do
      TestServer.start(scheme: :https)

      bad_host_url = TestServer.url(host: "bad-host.localhost")
      req_opts = [connect_options: [transport_opts: [cacerts: TestServer.x509_suite().cacerts]]]

      assert {:error, %TransportError{reason: {:tls_alert, {:handshake_failure, _error}}}} = Req.request(:get, bad_host_url, nil, [], req_opts)
    end

    test "handles SSL with bad certificate and no verification" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      bad_host_url = TestServer.url(host: "bad-host.localhost")
      req_opts = [connect_options: [transport_opts: [cacerts: TestServer.x509_suite().cacerts, verify: :verify_none]]]

      assert {:ok, %HTTPResponse{status: 200}} = Req.request(:get, bad_host_url, nil, [], req_opts)
    end

    test "handles unreachable host" do
      TestServer.start()
      url = TestServer.url()
      TestServer.stop()

      assert {:error, %TransportError{reason: :econnrefused}} = Req.request(:get, url, nil, [], retry: false)
    end

    test "handles query in URL" do
      TestServer.add("/get", via: :get, to: fn conn ->
        assert conn.query_string == "a=1"

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Req.request(:get, TestServer.url("/get?a=1"), nil, [])
    end

    test "handles POST" do
      TestServer.add("/post", via: :post, to: fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        assert params["a"] == "1"
        assert params["b"] == "2"
        assert Plug.Conn.get_req_header(conn, "content-type") == ["application/x-www-form-urlencoded"]

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert {:ok, %HTTPResponse{status: 200}} = Req.request(:post, TestServer.url("/post"), "a=1&b=2", [{"content-type", "application/x-www-form-urlencoded"}])
    end
  end
end
