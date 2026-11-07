defmodule Assent.HTTPAdapter.HttpcTest do
  use ExUnit.Case

  doctest Assent.HTTPAdapter.Httpc

  alias Assent.HTTPAdapter.{Httpc, HTTPResponse}

  @httpc_opts []

  describe "request/5" do
    test "with network error" do
      TestServer.start()
      url = TestServer.url()
      TestServer.stop()

      assert {:error, {:failed_connect, error}} = Httpc.request(:get, url, nil, [], @httpc_opts)

      assert inet_error(error) == :econnrefused
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
               Httpc.request(:get, TestServer.url("/get?a=1"), nil, [], @httpc_opts)
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
               Httpc.request(:get, TestServer.url(), nil, [], @httpc_opts)

      assert {"x-header", "value"} in headers
    end

    test "with redirect response" do
      TestServer.start()
      location = TestServer.url("/redirected")

      TestServer.add("/",
        via: :get,
        to: fn conn ->
          conn
          |> Plug.Conn.put_resp_header("location", location)
          |> Plug.Conn.send_resp(302, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 302}} =
               Httpc.request(:get, TestServer.url(), nil, [], @httpc_opts)
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

          assert Plug.Conn.get_req_header(conn, "content-length") == ["7"]

          Plug.Conn.send_resp(conn, 200, "")
        end
      )

      assert {:ok, %HTTPResponse{status: 200}} =
               Httpc.request(
                 :post,
                 TestServer.url("/post"),
                 "a=1&b=2",
                 [
                   {"content-type", "application/x-www-form-urlencoded"}
                 ],
                 @httpc_opts
               )
    end

    @tag :tmp_dir
    test "with HTTPS request with no other dependency starting `:ssl`", %{tmp_dir: tmp_dir} do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      cacerts_path = write_test_cacerts(tmp_dir)

      code =
        """
        {:ok, %{status: 200}} =
          Assent.HTTPAdapter.Httpc.request(:get, "#{TestServer.url()}", nil, [],
            ssl: [cacertfile: ~c"#{cacerts_path}"]
          )
        """

      assert {_stdout, 0} = mix_run(tmp_dir, code)
    end

    test "with HTTPS request with `ssl: [verify: :verify_none]` option" do
      httpc_opts = Keyword.put(@httpc_opts, :ssl, verify: :verify_none)

      assert_raise ArgumentError,
                   "expected `:verify` in `:ssl` options to be `:verify_peer`, got: :verify_none",
                   fn ->
                     Httpc.request(:get, "https://localhost", nil, [], httpc_opts)
                   end
    end

    test "with HTTPS request with `ssl: [cacerts: ...]` option" do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      httpc_opts = Keyword.put(@httpc_opts, :ssl, cacerts: TestServer.x509_suite().cacerts)

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} =
               Httpc.request(:get, TestServer.url(), nil, [], httpc_opts)
    end

    @tag :tmp_dir
    test "with HTTPS request with `ssl: [cacertfile: ...]` option", %{tmp_dir: tmp_dir} do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)

      cacerts_path = write_test_cacerts(tmp_dir)
      httpc_opts = Keyword.put(@httpc_opts, :ssl, cacertfile: ~c"#{cacerts_path}")

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} =
               Httpc.request(:get, TestServer.url(), nil, [], httpc_opts)
    end

    @tag :tmp_dir
    test "with HTTPS request with a hostname mismatch with `ssl: [verify_fun: ...]`", %{
      tmp_dir: tmp_dir
    } do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)
      setup_os_cacerts(tmp_dir)

      bad_host_url = TestServer.url(host: "bad-host.localhost")

      httpc_opts =
        Keyword.put(@httpc_opts, :ssl,
          verify_fun: {
            fn
              _cert, {:bad_cert, :hostname_check_failed}, state ->
                {:valid, state}

              _cert, {:bad_cert, reason}, _state ->
                {:fail, reason}

              _cert, {:extension, _extension}, state ->
                {:unknown, state}

              _cert, :valid, state ->
                {:valid, state}

              _cert, :valid_peer, state ->
                {:valid, state}
            end,
            nil
          }
        )

      assert {:ok, %HTTPResponse{status: 200}} =
               Httpc.request(:get, bad_host_url, nil, [], httpc_opts)
    end

    @tag :tmp_dir
    test "with HTTPS request with a hostname mismatch", %{tmp_dir: tmp_dir} do
      TestServer.start(scheme: :https)
      setup_os_cacerts(tmp_dir)

      bad_host_url = TestServer.url(host: "bad-host.localhost")

      assert {:error, {:failed_connect, error}} =
               Httpc.request(:get, bad_host_url, nil, [], @httpc_opts)

      assert {:tls_alert, _bad_certificate} = inet_error(error)
    end

    test "with HTTPS request with an untrusted certificate" do
      TestServer.start(scheme: :https)

      assert {:error, {:failed_connect, error}} =
               Httpc.request(:get, TestServer.url(), nil, [], @httpc_opts)

      assert {:tls_alert, _bad_certificate} = inet_error(error)
    end

    @tag :tmp_dir
    test "with HTTPS request with default SSL options", %{tmp_dir: tmp_dir} do
      TestServer.start(scheme: :https)
      TestServer.add("/", via: :get)
      setup_os_cacerts(tmp_dir)

      assert {:ok, %HTTPResponse{status: 200, body: "HTTP/1.1"}} =
               Httpc.request(:get, TestServer.url(), nil, [], @httpc_opts)
    end
  end

  defp inet_error([_, {:inet, [:inet], error}]), do: error

  defp mix_run(tmp_dir, code) do
    deps = ["{:assent, path: \"#{File.cwd!()}\"}"]
    test_app_dir = Path.join(tmp_dir, "test_app")
    :ok = File.mkdir_p!(test_app_dir)

    File.write!(
      Path.join(test_app_dir, "mix.exs"),
      """
      defmodule TestApp.MixProject do
        use Mix.Project

        def project do
          [
            app: :test_app,
            version: "0.1.0",
            deps_path: "#{Path.join(File.cwd!(), "deps")}",
            deps: [#{Enum.join(deps, ",")}]
          ]
        end
      end
      """
    )

    File.cd!(test_app_dir, fn ->
      {_stdout, 0} = System.cmd("mix", ["deps.get"])
      {_stdout, 0} = System.cmd("mix", ["compile"])

      System.cmd("mix", ["run", "-e", code], stderr_to_stdout: true)
    end)
  end

  defp write_test_cacerts(tmp_dir) do
    path = Path.join(tmp_dir, "cacerts.pem")

    pem =
      TestServer.x509_suite().cacerts
      |> Enum.map(&{:Certificate, &1, :not_encrypted})
      |> :public_key.pem_encode()

    :ok = File.write!(path, pem)

    path
  end

  defp setup_os_cacerts(tmp_dir) do
    # Replace the OS trust store with Test Server's CA certificates
    :ok = :public_key.cacerts_load(write_test_cacerts(tmp_dir))
    :ok = on_exit(fn -> :public_key.cacerts_clear() end)
  end
end
