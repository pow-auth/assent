defmodule Assent.HTTPAdapter.ReqTest do
  use Assent.TestCase
  doctest Assent.HTTPAdapter.Req

  alias Assent.HTTPAdapter.{HTTPResponse, Req}
  alias Elixir.Req.{FinchSupervisor, TransportError}

  # Test retries quickly
  @req_opts [retry_delay: 0, retry_log_level: false]

  # HTTP2 pools will cause logger warnings when the test server is stopped so
  # we must terminate them after each test
  setup do
    on_exit(fn ->
      for {_, pid, _, _} <- DynamicSupervisor.which_children(FinchSupervisor) do
        DynamicSupervisor.terminate_child(FinchSupervisor, pid)
      end
    end)

    :ok
  end

  describe "request/4" do
    test "with network error" do
      TestServer.start()
      url = TestServer.url()
      TestServer.stop()

      assert {:error, %TransportError{reason: :econnrefused}} =
               Req.request(:get, url, nil, [], retry: false)
    end

    test "with response headers" do
      TestServer.add("/",
        via: :get,
        to: fn conn ->
          conn
          |> Plug.Conn.put_resp_header("x-header", "value")
          |> Plug.Conn.send_resp(200, "")
        end
      )

      assert {:ok, %HTTPResponse{headers: headers}} =
               Req.request(:get, TestServer.url(), nil, [], @req_opts)

      assert {"x-header", "value"} in headers
    end

    test "with POST request" do
      TestServer.add("/post",
        via: :post,
        to: fn conn ->
          {:ok, body, conn} = Plug.Conn.read_body(conn, [])
          params = URI.decode_query(body)

          assert params["a"] == "1"
          assert params["b"] == "2"

          assert Plug.Conn.get_req_header(conn, "content-type") == [
                   "application/x-www-form-urlencoded"
                 ]

          Plug.Conn.send_resp(conn, 200, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 200}} =
               Req.request(
                 :post,
                 TestServer.url("/post"),
                 "a=1&b=2",
                 [
                   {"content-type", "application/x-www-form-urlencoded"}
                 ],
                 @req_opts
               )
    end

    test "with URL containing query" do
      TestServer.add("/get",
        via: :get,
        to: fn conn ->
          assert conn.query_string == "a=1"

          Plug.Conn.send_resp(conn, 200, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 200}} =
               Req.request(:get, TestServer.url("/get?a=1"), nil, [], @req_opts)
    end

    test "with HTTPS request with bad certificate" do
      TestServer.start(scheme: :https)

      bad_host_url = TestServer.url(host: "bad-host.localhost")

      req_opts =
        Keyword.put(
          @req_opts,
          :connect_options,
          transport_opts: [cacerts: TestServer.x509_suite().cacerts]
        )

      assert {:error, %TransportError{reason: {:tls_alert, _bad_certificate}}} =
               Req.request(:get, bad_host_url, nil, [], req_opts)
    end

    test "with HTTPS request with bad certificate with no verification" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      bad_host_url = TestServer.url(host: "bad-host.localhost")

      req_opts =
        Keyword.put(
          @req_opts,
          :connect_options,
          transport_opts: [cacerts: TestServer.x509_suite().cacerts, verify: :verify_none]
        )

      assert {:ok, %HTTPResponse{status: 200}} =
               Req.request(:get, bad_host_url, nil, [], req_opts)
    end

    test "with HTTPS request" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      req_opts =
        @req_opts
        |> Keyword.put(:retry_delay, 50)
        |> Keyword.put(
          :connect_options,
          transport_opts: [cacerts: TestServer.x509_suite().cacerts],
          protocols: [:http2]
        )

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/2"}} =
               Req.request(:get, TestServer.url(), nil, [], req_opts)
    end
  end
end
