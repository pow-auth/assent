defmodule IntegrationServer.Router do
  use Plug.Router
  use Plug.Debugger
  use Plug.ErrorHandler

  require Logger

  import Plug.Conn

  @session_options [
    store: :cookie,
    key: "_assent_integration_server",
    signing_salt: "Q1OaP6Pz",
    same_site: "Lax"
  ]

  plug :secret_key_base
  plug Plug.Session, @session_options
  plug :fetch_session
  plug :match
  plug :dispatch

  {:ok, modules} = :application.get_key(:assent, :modules)

  @path_modules modules
                |> Enum.map(&{Module.split(&1), &1})
                |> Enum.map(fn
                  {["Assent", "Strategy", uri], module} ->
                    path = Macro.underscore(uri)
                    fun_name = String.to_atom(path)
                    {path, module, fun_name}

                  _any ->
                    nil
                end)
                |> Enum.reject(&is_nil/1)

  defp secret_key_base(conn, _opts) do
    %{conn | secret_key_base: "LG8WiSkAlUlwVJpISmRYsi7aJV/Qlv65FXyxwWXxp1QUzQY3hzEfg73YKfKZPpe0"}
  end

  for {path, module, fun_name} <- @path_modules do
    @file "#{__ENV__.file}##{path}_auth"
    defp unquote(fun_name)(conn, :auth) do
      unquote(path)
      |> config!()
      |> unquote(module).authorize_url()
      |> handle_authorize_url(conn)
    end

    @file "#{__ENV__.file}##{path}_callback"
    defp unquote(fun_name)(conn, :callback) do
      conn = fetch_query_params(conn)

      unquote(path)
      |> config!()
      |> Keyword.put(:session_params, get_session(conn, :session_params))
      |> unquote(module).callback(conn.params)
      |> handle_callback(conn)
    end
  end

  defp handle_authorize_url({:ok, res}, conn) do
    session_params = res[:session_params]

    Logger.info(
      "Redirecting to #{inspect(res.url)} with session params #{inspect(session_params)}"
    )

    html = Plug.HTML.html_escape(res.url)
    body = "<html><body>You are being <a href=\"#{html}\">redirected</a>.</body></html>"

    conn
    |> put_session(:session_params, session_params)
    |> put_resp_header("location", res.url)
    |> put_resp_header("content-type", "text/html")
    |> send_resp(302, body)
  end

  defp handle_authorize_url({:error, error}, conn) do
    body = "<html><body>An error occurred: #{inspect(error)}.</body></html>"

    conn
    |> put_resp_header("content-type", "text/html")
    |> send_resp(500, body)
  end

  defp handle_callback({:ok, res}, conn) do
    body = "<html><body>#{inspect(Map.take(res, [:user, :token]))}</body></html>"

    send_resp(conn, 200, body)
  end

  defp handle_callback({:error, error}, conn) do
    body = "<html><body>An error occurred: #{inspect(error)}.</body></html>"

    conn
    |> put_resp_header("content-type", "text/html")
    |> send_resp(500, body)
  end

  get "/" do
    list =
      @path_modules
      |> Enum.map(&"<li><a href=\"/#{elem(&1, 0)}\">#{elem(&1, 0)}</a></li>")
      |> Enum.join()

    body = "<html><body><ul>#{list}</ul></body></html>"

    send_resp(conn, 200, body)
  end

  for {path, _module, fun_name} <- @path_modules do
    get "/#{path}", do: unquote(fun_name)(conn, :auth)
    get "/#{path}/callback", do: unquote(fun_name)(conn, :callback)
  end

  def config!(path) do
    [
      client_id: System.fetch_env!("CLIENT_ID"),
      client_secret: System.fetch_env!("CLIENT_SECRET"),
      redirect_uri: "http://localhost:4000/#{path}/callback"
    ]
  end

  @impl true
  def handle_errors(conn, %{kind: _kind, reason: _reason, stack: _stack}) do
    send_resp(conn, conn.status, "Something went wrong")
  end
end
