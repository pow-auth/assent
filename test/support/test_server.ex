defmodule Assent.TestServer do
  @moduledoc false

  alias Plug.Conn

  @protocol_options [
    idle_timeout: 1000,
    request_timeout: 1000
  ]

  @https_options [
    keyfile: Path.expand("tmp/fixtures/ssl/server_key.pem"),
    certfile: Path.expand("tmp/fixtures/ssl/valid.pem"),
    cacertfile: Path.expand("tmp/fixtures/ssl/ca_and_chain.pem")
  ]

  @cacertfile Path.expand("tmp/fixtures/ssl/cacerts.pem")

  # API

  def expect(method, uri, callback_fn \\ nil) do
    callback_fn = callback_fn || &Plug.Conn.send_resp(&1, 200, to_string(Plug.Conn.get_http_protocol(&1)))

    case GenServer.call(get_or_set_pid(), {:put, method, uri, callback_fn}) do
      :ok -> :ok
      :error -> raise "Route expectation has already been set for #{method} #{uri}"
    end
  end

  defp get_or_set_pid do
    case Process.get(:test_server) do
      nil -> setup()
      pid -> pid
    end
  end

  def setup(opts \\ []) do
    port = open_port()
    opts = Keyword.merge([scheme: :http, cert: :valid, port: port], opts)
    cowboy_options = cowboy_options(opts)

    {:ok, pid} = GenServer.start(__MODULE__.Instance, opts)
    {:ok, _} = apply(Plug.Cowboy, opts[:scheme], [__MODULE__.Plug, [pid], Keyword.put(cowboy_options, :ref, cowboy_ref(pid))])

    Process.put(:test_server, pid)

    ExUnit.Callbacks.on_exit(fn ->
      case Map.keys(GenServer.call(pid, :expectations)) do
        [] -> :ok
        routes -> raise "No requests arrived for these routes: #{inspect routes}"
      end

      Process.delete(:test_server)
      Plug.Cowboy.shutdown(cowboy_ref(pid))
      :ok = GenServer.stop(pid)
    end)

    pid
  end

  defp open_port do
    {:ok, socket} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(socket)
    true = :erlang.port_close(socket)

    port
  end

  defp cowboy_options(opts) do
    options = [port: opts[:port], protocol_options: @protocol_options]

    case opts[:scheme] do
      :https -> Keyword.merge(options, @https_options)
      :http -> options
    end
  end

  defp cowboy_ref(pid) do
    port = fetch_option!(pid, :port)
    Module.concat(__MODULE__.Plug, "Server_#{port}")
  end

  defp fetch_option!(pid, key) do
    Keyword.fetch!(GenServer.call(pid, :opts), key)
  end

  def url(uri) when is_binary(uri), do: url(uri, [])
  def url(opts) when is_list(opts), do: url(nil, opts)
  def url(uri \\ nil, opts \\ []) do
    domain =
      case opts[:domain] do
        nil ->
          "localhost"

        domain ->
          :inet_db.set_lookup([:file, :dns])
          :inet_db.add_host({127, 0, 0, 1}, [String.to_charlist(domain)])

          domain
      end

    port = fetch_option!(get_or_set_pid(), :port)
    scheme = fetch_option!(get_or_set_pid(), :scheme)

    "#{scheme}://#{domain}:#{port}#{uri}"
  end

  def cacertfile, do: @cacertfile

  def down do
    pid = Process.get(:test_server)
    ref = cowboy_ref(pid)

    :ok = Plug.Cowboy.shutdown(ref)
  end

  # GenServer instance

  defmodule Instance do
    @moduledoc false

    use GenServer

    def start_link(options \\ []) do
      GenServer.start_link(__MODULE__, options)
    end

    def init(options) do
      {:ok, %{options: options, expectations: %{}}}
    end

    def handle_call(:opts, _from, state) do
      {:reply, state.options, state}
    end

    def handle_call(:expectations, _from, state) do
      {:reply, state.expectations, state}
    end

    def handle_call({:put, method, uri, callback_fn}, _from, state) do
      key = "#{method}:#{uri}"

      case Map.has_key?(state.expectations, key) do
        false ->
          expectations = Map.put(state.expectations, key, callback_fn)

          {:reply, :ok, %{state | expectations: expectations}}

        true ->
          {:reply, :error, state}
      end
    end

    def handle_call({:get, method, uri}, _from, state) do
      key = "#{method}:#{uri}"


      case Map.has_key?(state.expectations, key) do
        false ->
          {:reply, :error, state}

        true ->
          {callback_fn, expectations} = Map.pop(state.expectations, key)

          {:reply, {:ok, callback_fn}, %{state | expectations: expectations}}
      end
    end
  end

  # Plug

  defmodule Plug do
    @moduledoc false

    def init([pid]), do: pid

    def call(conn, pid) do
      case GenServer.call(pid, {:get, conn.method, conn.request_path}, :infinity) do
        {:ok, callback_fn} ->
          Process.put(:test_server, pid)

          conn = Conn.fetch_query_params(conn)

          callback_fn.(conn)

        :error ->
          raise  "No route for #{conn.method} #{conn.request_path}"
      end
    end
  end
end
