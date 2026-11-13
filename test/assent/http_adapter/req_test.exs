defmodule Assent.HTTPAdapter.ReqTest do
  use ExUnit.Case

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

  describe "request/5" do
    test "with network error" do
      TestServer.HTTP.start()
      url = TestServer.HTTP.url()
      TestServer.HTTP.stop()

      assert {:error, %TransportError{reason: :econnrefused}} =
               Req.request(:get, url, nil, [], retry: false)
    end

    test "with response headers" do
      TestServer.HTTP.handle("/",
        method: :get,
        to: fn conn ->
          conn
          |> Plug.Conn.put_resp_header("x-header", "value")
          |> Plug.Conn.send_resp(200, "")
        end
      )

      assert {:ok, %HTTPResponse{headers: headers}} =
               Req.request(:get, TestServer.HTTP.url(), nil, [], @req_opts)

      assert {"x-header", "value"} in headers
    end

    test "with redirect response" do
      TestServer.HTTP.start()
      location = TestServer.HTTP.url("/redirected")

      TestServer.HTTP.handle("/",
        method: :get,
        to: fn conn ->
          conn
          |> Plug.Conn.put_resp_header("location", location)
          |> Plug.Conn.send_resp(302, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 302}} =
               Req.request(:get, TestServer.HTTP.url(), nil, [], @req_opts)
    end

    test "with POST request" do
      TestServer.HTTP.handle("/post",
        method: :post,
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
                 TestServer.HTTP.url("/post"),
                 "a=1&b=2",
                 [
                   {"content-type", "application/x-www-form-urlencoded"}
                 ],
                 @req_opts
               )
    end

    test "with URL containing query" do
      TestServer.HTTP.handle("/get",
        method: :get,
        to: fn conn ->
          assert conn.query_string == "a=1"

          Plug.Conn.send_resp(conn, 200, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 200}} =
               Req.request(:get, TestServer.HTTP.url("/get?a=1"), nil, [], @req_opts)
    end

    test "with HTTPS request with bad certificate" do
      TestServer.HTTP.start(scheme: :https)

      bad_host_url = TestServer.HTTP.url(host: "bad-host.localhost")

      req_opts =
        Keyword.put(
          @req_opts,
          :connect_options,
          transport_opts: [cacerts: TestServer.HTTP.cacerts()]
        )

      assert {:error, %TransportError{reason: {:tls_alert, _bad_certificate}}} =
               Req.request(:get, bad_host_url, nil, [], req_opts)
    end

    test "with HTTPS request with bad certificate and disabled verification" do
      TestServer.HTTP.start(scheme: :https)
      TestServer.HTTP.handle("/", method: :get)

      bad_host_url = TestServer.HTTP.url(host: "bad-host.localhost")

      req_opts =
        Keyword.put(
          @req_opts,
          :connect_options,
          transport_opts: [cacerts: TestServer.HTTP.cacerts(), verify: :verify_none]
        )

      assert {:ok, %HTTPResponse{status: 200}} =
               Req.request(:get, bad_host_url, nil, [], req_opts)
    end

    test "with HTTPS request" do
      TestServer.HTTP.start(scheme: :https)
      TestServer.HTTP.handle("/", method: :get)

      req_opts =
        @req_opts
        |> Keyword.put(:retry_delay, 50)
        |> Keyword.put(
          :connect_options,
          transport_opts: [cacerts: TestServer.HTTP.cacerts()],
          protocols: [:http2]
        )

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/2"}} =
               Req.request(:get, TestServer.HTTP.url(), nil, [], req_opts)
    end
  end
end
