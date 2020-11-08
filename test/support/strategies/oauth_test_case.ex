defmodule Assent.Test.OAuthTestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  setup _context do
    params = %{"oauth_token" => "hh5s93j4hdidpola", "oauth_verifier" => "hfdp7dh39dks9884"}
    bypass = Bypass.open()
    config = [consumer_key: "dpf43f3p2l4k3l03", consumer_secret: "kd94hf93k423kf44", site: "http://localhost:#{bypass.port}", redirect_uri: "http://localhost:4000/auth/callback", session_params: %{oauth_token_secret: "request_token_secret"}]

    {:ok, callback_params: params, config: config, bypass: bypass}
  end

  using do
    quote do
      use ExUnit.Case

      import unquote(__MODULE__)
    end
  end

  alias Plug.Conn

  @spec expect_oauth_request_token_request(Bypass.t(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth_request_token_request(bypass, opts \\ [], assert_fn \\ nil) do
    response = Keyword.get(opts, :params, %{oauth_token: "hh5s93j4hdidpola", oauth_token_secret: "hdhd0244k9j7ao03"})
    uri      = Keyword.get(opts, :uri, "/request_token")

    expect_oauth_request(bypass, "POST", uri, opts, response, assert_fn)
  end

  defp expect_oauth_request(bypass, method, uri, opts, response, assert_fn) do
    status_code    = Keyword.get(opts, :status_code, 200)
    content_type   = Keyword.get(opts, :content_type, "application/x-www-form-urlencoded")

    response =
      case content_type do
        "application/x-www-form-urlencoded" -> URI.encode_query(response)
        "application/json"                  -> Jason.encode!(response)
        _any                                -> response
      end

    Bypass.expect_once(bypass, method, uri, fn conn ->
      if assert_fn, do: assert_fn.(conn, parse_auth_header(conn))

      conn
      |> Conn.put_resp_content_type(content_type)
      |> Conn.resp(status_code, response)
    end)
  end

  @spec expect_oauth_access_token_request(Bypass.t(), Keyword.t()) :: :ok
  def expect_oauth_access_token_request(bypass, opts \\ [], assert_fn \\ nil) do
    params = Keyword.get(opts, :params, %{oauth_token: "token", oauth_token_secret: "token_secret"})
    uri    = Keyword.get(opts, :uri, "/access_token")

    expect_oauth_request(bypass, "POST", uri, opts, params, assert_fn)
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

  @spec expect_oauth_user_request(Bypass.t(), map(), Keyword.t()) :: :ok
  def expect_oauth_user_request(bypass, user_params, opts \\ [], assert_fn \\ nil) do
    uri  = Keyword.get(opts, :uri, "/api/user")
    opts = Keyword.put(opts, :content_type, "application/json")

    expect_oauth_request(bypass, "GET", uri, opts, user_params, assert_fn)
  end

  @spec expect_oauth_api_request(Bypass.t(), binary(), map(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth_api_request(bypass, uri, response, opts \\ [], assert_fn \\ nil, method \\ "GET") do
    opts = Keyword.put(opts, :content_type, "application/json")

    expect_oauth_request(bypass, method, uri, opts, response, assert_fn)
  end
end
