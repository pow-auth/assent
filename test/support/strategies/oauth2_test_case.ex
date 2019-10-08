defmodule Assent.Test.OAuth2TestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  setup _tags do
    params = %{"code" => "test", "state" => "test"}
    bypass = Bypass.open()
    config = [client_id: "id", client_secret: "secret", site: "http://localhost:#{bypass.port}", redirect_uri: "http://localhost:4000/auth/callback", session_params: %{state: "test"}]

    {:ok, callback_params: params, config: config, bypass: bypass}
  end

  using do
    quote do
      use ExUnit.Case

      import unquote(__MODULE__)
    end
  end

  alias Plug.Conn

  @spec expect_oauth2_access_token_request(Bypass.t(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth2_access_token_request(bypass, opts \\ [], assert_fn \\ nil) do
    access_token = Keyword.get(opts, :access_token, "access_token")
    token_params = Keyword.get(opts, :params, %{access_token: access_token})
    uri          = Keyword.get(opts, :uri, "/oauth/token")
    status_code  = Keyword.get(opts, :status_code, 200)

    Bypass.expect_once(bypass, "POST", uri, fn conn ->
      {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
      params = URI.decode_query(body)

      if assert_fn, do: assert_fn.(conn, params)

      send_json_resp(conn, token_params, status_code)
    end)
  end

  @spec expect_oauth2_user_request(Bypass.t(), map(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth2_user_request(bypass, user_params, opts \\ [], assert_fn \\ nil) do
    uri          = Keyword.get(opts, :uri, "/api/user")

    expect_oauth2_api_request(bypass, uri, user_params, opts, assert_fn)
  end

  @spec expect_oauth2_api_request(Bypass.t(), binary(), map(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth2_api_request(bypass, uri, response, opts \\ [], assert_fn \\ nil) do
    access_token = Keyword.get(opts, :access_token, "access_token")
    status_code  = Keyword.get(opts, :status_code, 200)

    Bypass.expect_once(bypass, "GET", uri, fn conn ->
      if assert_fn, do: assert_fn.(conn)

      assert_bearer_token_in_header(conn, access_token)

      send_json_resp(conn, response, status_code)
    end)
  end

  defp assert_bearer_token_in_header(conn, token) do
    expected = {"authorization", "Bearer #{token}"}

    case Enum.find(conn.req_headers, &(elem(&1, 0) == "authorization")) do
      ^expected ->
        true

      {"authorization", "Bearer " <> found_token} ->
        ExUnit.Assertions.flunk("Expected bearer token #{token}, but received #{found_token}")

      _ ->
        ExUnit.Assertions.flunk("No bearer token found in headers")
    end
  end

  defp send_json_resp(conn, body, status_code) do
    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(status_code, Jason.encode!(body))
  end
end
