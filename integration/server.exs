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
                  {["Assent", "Strategy", uri], module} -> {uri, module}
                  _any -> nil
                end)
                |> Enum.reject(&is_nil/1)
                |> Enum.into(%{})

  defp secret_key_base(conn, _opts) do
    %{conn | secret_key_base: "LG8WiSkAlUlwVJpISmRYsi7aJV/Qlv65FXyxwWXxp1QUzQY3hzEfg73YKfKZPpe0"}
  end

  get "/" do
    list =
      @path_modules
      |> Enum.map(&"<li><a href=\"/#{elem(&1, 0)}\">#{elem(&1, 0)}</a></li>")
      |> Enum.join()

    body = "<html><body><ul>#{list}</ul></body></html>"

    send_resp(conn, 200, body)
  end

  get "/:provider" do
    module = Map.fetch!(@path_modules, provider)

    {:ok, %{url: url, session_params: session_params}} = module.authorize_url(config!(provider))

    Logger.info("Redirecting to #{inspect(url)} with session params #{inspect(session_params)}")

    html = Plug.HTML.html_escape(url)
    body = "<html><body>You are being <a href=\"#{html}\">redirected</a>.</body></html>"

    conn
    |> put_session(:session_params, session_params)
    |> put_resp_header("location", url)
    |> put_resp_header("content-type", "text/html")
    |> send_resp(302, body)
  end

  get "/:provider/callback" do
    module = Map.fetch!(@path_modules, provider)

    conn = fetch_query_params(conn)

    {:ok, %{user: user, token: token}} =
      provider
      |> config!()
      |> Assent.Config.put(:session_params, get_session(conn, :session_params))
      |> module.callback(conn.params)

    body = "<html><body>#{inspect(%{user: user, token: token})}</body></html>"

    send_resp(conn, 200, body)
  end

  def config!(provider) do
    [
      client_id: System.fetch_env!("CLIENT_ID"),
      client_secret: System.fetch_env!("CLIENT_SECRET"),
      redirect_uri: "http://localhost:4000/#{provider}/callback"
    ]
  end

  defp handle_errors(conn, %{kind: _kind, reason: _reason, stack: _stack}) do
    send_resp(conn, conn.status, "Something went wrong")
  end
end

{:ok, pid} = Bandit.start_link(plug: IntegrationServer.Router)
Process.unlink(pid)
