defmodule Assent.Test.OAuthTestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  setup _context do
    TestServer.start()

    params = %{"oauth_token" => "hh5s93j4hdidpola", "oauth_verifier" => "hfdp7dh39dks9884"}

    config = [
      consumer_key: "dpf43f3p2l4k3l03",
      consumer_secret: "kd94hf93k423kf44",
      base_url: TestServer.url(),
      redirect_uri: "http://localhost:4000/auth/callback",
      session_params: %{oauth_token_secret: "request_token_secret"}
    ]

    {:ok, callback_params: params, config: config}
  end

  using do
    quote do
      use ExUnit.Case

      import unquote(__MODULE__)
    end
  end

  alias Plug.Conn

  @spec expect_oauth_request_token_request(Keyword.t(), function() | nil) :: :ok
  def expect_oauth_request_token_request(opts \\ [], assert_fn \\ nil) do
    response =
      Keyword.get(opts, :params, %{
        oauth_token: "hh5s93j4hdidpola",
        oauth_token_secret: "hdhd0244k9j7ao03"
      })

    uri = Keyword.get(opts, :uri, "/request_token")

    expect_oauth_request("POST", uri, opts, response, assert_fn)
  end

  defp expect_oauth_request(method, uri, opts, response, assert_fn) do
    status_code = Keyword.get(opts, :status_code, 200)
    content_type = Keyword.get(opts, :content_type, "application/x-www-form-urlencoded")

    response =
      case content_type do
        "application/x-www-form-urlencoded" -> URI.encode_query(response)
        "application/json" -> Jason.encode!(response)
        _any -> response
      end

    TestServer.add(uri,
      via: method,
      to: fn conn ->
        if assert_fn, do: assert_fn.(conn, parse_auth_header(conn))

        conn
        |> Conn.put_resp_content_type(content_type)
        |> Conn.resp(status_code, response)
      end
    )
  end

  @spec expect_oauth_access_token_request(Keyword.t()) :: :ok
  def expect_oauth_access_token_request(opts \\ [], assert_fn \\ nil) do
    params =
      Keyword.get(opts, :params, %{oauth_token: "token", oauth_token_secret: "token_secret"})

    uri = Keyword.get(opts, :uri, "/access_token")

    expect_oauth_request("POST", uri, opts, params, assert_fn)
  end

  defp parse_auth_header(conn) do
    {_, value} = List.keyfind(conn.req_headers, "authorization", 0)

    value
    |> String.slice(6..-1)
    |> String.split(",")
    |> Enum.into(%{}, fn string ->
      [_, key, value] = Regex.run(~r/^([a-zA-Z_]+)=\"(.*?)\"$/i, String.trim(string))

      {key, value}
    end)
  end

  @spec expect_oauth_user_request(map(), Keyword.t()) :: :ok
  def expect_oauth_user_request(user_params, opts \\ [], assert_fn \\ nil) do
    uri = Keyword.get(opts, :uri, "/api/user")
    opts = Keyword.put(opts, :content_type, "application/json")

    expect_oauth_request("GET", uri, opts, user_params, assert_fn)
  end

  @spec expect_oauth_api_request(binary(), map(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth_api_request(uri, response, opts \\ [], assert_fn \\ nil, method \\ "GET") do
    opts = Keyword.put(opts, :content_type, "application/json")

    expect_oauth_request(method, uri, opts, response, assert_fn)
  end
end
