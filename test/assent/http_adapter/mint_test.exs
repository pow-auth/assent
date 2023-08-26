defmodule Assent.HTTPAdapter.MintTest do
  use ExUnit.Case
  doctest Assent.HTTPAdapter.Mint

  alias ExUnit.CaptureIO
  alias Mint.TransportError
  alias Assent.HTTPAdapter.{HTTPResponse, Mint}

  describe "request/4" do
    test "handles SSL" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      mint_opts = [transport_opts: [cacerts: TestServer.x509_suite().cacerts], protocols: [:http1]]

      assert CaptureIO.capture_io(:stderr, fn ->
        assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} = Mint.request(:get, TestServer.url(), nil, [], mint_opts)
      end) =~ "Assent.HTTPAdapter.Mint is deprecated, consider use Assent.HTTPAdapter.Finch instead"
    end

    test "handles SSL with bad certificate" do
      TestServer.start(scheme: :https)

      bad_host_url = TestServer.url(host: "bad-host.localhost")
      mint_opts = [transport_opts: [cacerts: TestServer.x509_suite().cacerts]]

      assert CaptureIO.capture_io(:stderr, fn ->
        assert {:error, %TransportError{reason: {:tls_alert, {:handshake_failure, _error}}}} = Mint.request(:get, bad_host_url, nil, [], mint_opts)
      end) =~ "Assent.HTTPAdapter.Mint is deprecated, consider use Assent.HTTPAdapter.Finch instead"
    end

    test "handles SSL with bad certificate and no verification" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      bad_host_url = TestServer.url(host: "bad-host.localhost")
      mint_opts = [transport_opts: [cacerts: TestServer.x509_suite().cacerts, verify: :verify_none]]

      assert CaptureIO.capture_io(:stderr, fn ->
        assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, bad_host_url, nil, [], mint_opts)
      end) =~ "Assent.HTTPAdapter.Mint is deprecated, consider use Assent.HTTPAdapter.Finch instead"
    end

    if :crypto.supports()[:curves] do
      test "handles http/2" do
        TestServer.start(scheme: :https)
        TestServer.add("/", via: :get)

        mint_opts = [transport_opts: [cacerts: TestServer.x509_suite().cacerts]]

        assert CaptureIO.capture_io(:stderr, fn ->
          assert {:ok, %HTTPResponse{status: 200, body: "HTTP/2"}} = Mint.request(:get, TestServer.url(), nil, [], mint_opts)
        end) =~ "Assent.HTTPAdapter.Mint is deprecated, consider use Assent.HTTPAdapter.Finch instead"
      end
    else
      IO.warn("No support curve algorithms, can't test in #{__MODULE__}")
    end

    test "handles unreachable host" do
      TestServer.start()
      url = TestServer.url()
      TestServer.stop()

      assert CaptureIO.capture_io(:stderr, fn ->
        assert {:error, %TransportError{reason: :econnrefused}} = Mint.request(:get, url, nil, [])
      end) =~ "Assent.HTTPAdapter.Mint is deprecated, consider use Assent.HTTPAdapter.Finch instead"
    end

    test "handles query in URL" do
      TestServer.add("/get", via: :get, to: fn conn ->
        assert conn.query_string == "a=1"

        Plug.Conn.send_resp(conn, 200, "")
      end)

      assert CaptureIO.capture_io(:stderr, fn ->
        assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:get, TestServer.url("/get?a=1"), nil, [])
      end) =~ "Assent.HTTPAdapter.Mint is deprecated, consider use Assent.HTTPAdapter.Finch instead"
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

      assert CaptureIO.capture_io(:stderr, fn ->
        assert {:ok, %HTTPResponse{status: 200}} = Mint.request(:post, TestServer.url("/post"), "a=1&b=2", [{"content-type", "application/x-www-form-urlencoded"}])
      end) =~ "Assent.HTTPAdapter.Mint is deprecated, consider use Assent.HTTPAdapter.Finch instead"
    end
  end
end
