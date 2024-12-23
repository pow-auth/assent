defmodule Assent.HTTPAdapter.HttpcTest do
  use Assent.TestCase
  doctest Assent.HTTPAdapter.Httpc

  alias Assent.HTTPAdapter.{Httpc, HTTPResponse}

  describe "request/4" do
    test "handles SSL" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} =
               Httpc.request(:get, TestServer.url(), nil, [],
                 ssl: [cacerts: TestServer.x509_suite().cacerts]
               )

      File.mkdir_p!("tmp")

      File.write!(
        "tmp/cacerts.pem",
        :public_key.pem_encode(
          Enum.map(TestServer.x509_suite().cacerts, &{:Certificate, &1, :not_encrypted})
        )
      )

      TestServer.add("/", via: :get)

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} =
               Httpc.request(:get, TestServer.url(), nil, [],
                 ssl: [cacertfile: ~c"tmp/cacerts.pem"]
               )
    end

    test "handles SSL with bad certificate" do
      TestServer.start(scheme: :https)

      bad_host_url = TestServer.url(host: "bad-host.localhost")
      httpc_opts = [ssl: [cacerts: TestServer.x509_suite().cacerts]]

      assert {:error, {:failed_connect, error}} =
               Httpc.request(:get, bad_host_url, nil, [], httpc_opts)

      assert {:tls_alert, {:handshake_failure, _error}} = fetch_inet_error(error)
    end

    test "handles SSL with bad certificate and no verification" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      bad_host_url = TestServer.url(host: "bad-host.localhost")

      httpc_opts = [
        ssl: [
          cacerts: TestServer.x509_suite().cacerts,
          verify: :verify_none,
          verify_fun: {fn _cert, _event, state -> {:valid, state} end, nil}
        ]
      ]

      assert {:ok, %HTTPResponse{status: 200}} =
               Httpc.request(:get, bad_host_url, nil, [], httpc_opts)
    end

    test "with missing ssl_verify_fun" do
      error = request_with_deps(["{:certifi, \">= 0.0.0\"}"])

      assert error =~ "RuntimeError"
      assert error =~ "This request can NOT be verified for valid SSL certificate"
      assert error =~ "Please add `:ssl_verify_fun` to your projects dependencies"
      assert error =~ "ssl: [verify_peer: :verify_peer, verify_fun: ...]"
    end

    test "with missing cacerts" do
      error = request_with_deps(["{:ssl_verify_fun, \">= 0.0.0\"}"])

      assert error =~ "RuntimeError"
      assert error =~ "This request requires a CA trust store"
      assert error =~ "Please add `:certifi` to your projects dependencies"
      assert error =~ "ssl: [cacerts: ...]"
    end

    test "handles unreachable host" do
      TestServer.start()
      url = TestServer.url()
      TestServer.stop()

      assert {:error, {:failed_connect, error}} = Httpc.request(:get, url, nil, [])
      assert fetch_inet_error(error) == :econnrefused
    end

    test "handles query in URL" do
      TestServer.add("/get",
        via: :get,
        to: fn conn ->
          assert conn.query_string == "a=1"

          Plug.Conn.send_resp(conn, 200, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 200}} =
               Httpc.request(:get, TestServer.url("/get?a=1"), nil, [])
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

          assert Plug.Conn.get_req_header(conn, "content-length") == ["7"]

          Plug.Conn.send_resp(conn, 200, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 200}} =
               Httpc.request(:post, TestServer.url("/post"), "a=1&b=2", [
                 {"content-type", "application/x-www-form-urlencoded"}
               ])
    end
  end

  defp fetch_inet_error([_, {:inet, [:inet], error}]), do: error

  defp request_with_deps(deps) do
    deps = deps ++ ["{:assent, path: \"../../\"}"]

    File.rm_rf!("tmp/test_app")
    File.mkdir_p!("tmp/test_app")

    File.write!("tmp/test_app/mix.exs", """
    defmodule TestApp.MixProject do
      use Mix.Project

      def project do
        [
          app: :test_app,
          version: "0.1.0",
          deps_path: "../../deps",
          deps: [#{Enum.join(deps, ",")}]
        ]
      end
    end
    """)

    File.cd!("tmp/test_app", fn ->
      {_stdout, 0} = System.cmd("mix", ["deps.get"])
      {_stdout, 0} = System.cmd("mix", ["compile"])

      {stdout, 1} =
        System.cmd(
          "mix",
          ["run", "-e", "Assent.HTTPAdapter.Httpc.request(:get, \"https://localhost\", nil, [])"],
          stderr_to_stdout: true
        )

      stdout
    end)
  end
end
