defmodule Assent.TestServer do
  @moduledoc false

  alias Plug.Conn

  @protocol_options [
    idle_timeout: 1000,
    request_timeout: 1000
  ]

  # API

  def expect(method, uri, callback_fn) do
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

  defp setup do
    port = open_port()
    options = [port: port, protocol_options: @protocol_options]

    {:ok, pid} = GenServer.start(__MODULE__.Instance, options)
    {:ok, _} = Plug.Cowboy.http(__MODULE__.Plug, [pid], Keyword.put(options, :ref, cowboy_ref(pid)))

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

  defp cowboy_ref(pid) do
    port = GenServer.call(pid, :port)
    Module.concat(__MODULE__.Plug, "Server_#{port}")
  end

  def url(uri \\ nil) do
    port = GenServer.call(get_or_set_pid(), :port)

    "http://localhost:#{port}#{uri}"
  end

  def down do
    pid = Process.get(:test_server)

    :ok = Plug.Cowboy.shutdown(cowboy_ref(pid))
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

    def handle_call(:port, _from, state) do
      {:reply, state.options[:port], state}
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
