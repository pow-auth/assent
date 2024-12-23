defmodule Assent.HTTPAdapter.FinchTest do
  use Assent.TestCase
  doctest Assent.HTTPAdapter.Finch

  alias Assent.HTTPAdapter.Finch, as: FinchAdapter
  alias Assent.HTTPAdapter.HTTPResponse
  alias Finch.Error

  import ExUnit.CaptureLog

  describe "request/4" do
    test "without supervisor" do
      TestServer.start(scheme: :https)

      assert_raise RuntimeError,
                   "Missing `:supervisor` option for the Assent.HTTPAdapter.Finch configuration",
                   fn ->
                     FinchAdapter.request(:get, TestServer.url(), nil, [])
                   end
    end

    test "handles HTTP/1" do
      TestServer.add("/", via: :get)

      supervisor = start_supervised_finch!(protocols: [:http1])

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} =
               FinchAdapter.request(:get, TestServer.url(), nil, [], supervisor: supervisor)
    end

    test "handles SSL" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      supervisor =
        start_supervised_finch!(
          conn_opts: [transport_opts: [cacerts: TestServer.x509_suite().cacerts]]
        )

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/2"}} =
               FinchAdapter.request(:get, TestServer.url(), nil, [], supervisor: supervisor)
    end

    test "handles SSL with bad certificate" do
      TestServer.start(scheme: :https)

      supervisor =
        start_supervised_finch!(
          conn_opts: [transport_opts: [cacerts: TestServer.x509_suite().cacerts]]
        )

      bad_host_url = TestServer.url(host: "bad-host.localhost")

      assert capture_log(fn ->
               assert {:error, %Error{reason: :disconnected}} =
                        FinchAdapter.request(:get, bad_host_url, nil, [], supervisor: supervisor)
             end) =~ "hostname_check_failed"
    end

    test "handles SSL with bad certificate and no verification" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      supervisor =
        start_supervised_finch!(
          conn_opts: [
            transport_opts: [cacerts: TestServer.x509_suite().cacerts, verify: :verify_none]
          ]
        )

      bad_host_url = TestServer.url(host: "bad-host.localhost")

      assert {:ok, %HTTPResponse{status: 200}} =
               FinchAdapter.request(:get, bad_host_url, nil, [], supervisor: supervisor)
    end

    test "handles unreachable host" do
      TestServer.start()
      url = TestServer.url()
      TestServer.stop()

      supervisor = start_supervised_finch!()

      assert capture_log(fn ->
               assert {:error, %Error{reason: :disconnected}} =
                        FinchAdapter.request(:get, url, nil, [], supervisor: supervisor)
             end) =~ "connection refused"
    end

    test "handles query in URL" do
      TestServer.add("/get",
        via: :get,
        to: fn conn ->
          assert conn.query_string == "a=1"

          Plug.Conn.send_resp(conn, 200, "")
        end
      )

      supervisor = start_supervised_finch!()

      assert {:ok, %HTTPResponse{status: 200}} =
               FinchAdapter.request(:get, TestServer.url("/get?a=1"), nil, [],
                 supervisor: supervisor
               )
    end

    test "handles POST" do
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

      supervisor = start_supervised_finch!()

      assert {:ok, %HTTPResponse{status: 200}} =
               FinchAdapter.request(
                 :post,
                 TestServer.url("/post"),
                 "a=1&b=2",
                 [{"content-type", "application/x-www-form-urlencoded"}],
                 supervisor: supervisor
               )
    end
  end

  defp start_supervised_finch!(opts \\ []) do
    start_supervised!(
      {Finch, name: FinchTest, pools: %{:default => Keyword.put_new(opts, :protocols, [:http2])}}
    )

    FinchTest
  end
end
