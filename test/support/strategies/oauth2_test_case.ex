defmodule Assent.Test.OAuth2TestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  @json_library (Code.ensure_loaded?(JSON) && JSON) || Jason

  setup _tags do
    TestServer.start()

    params = %{"code" => "code_test_value", "state" => "state_test_value"}

    config = [
      client_id: "id",
      client_secret: "secret",
      base_url: TestServer.url(),
      redirect_uri: "http://localhost:4000/auth/callback",
      session_params: %{state: "state_test_value"}
    ]

    {:ok, callback_params: params, config: config}
  end

  using do
    quote do
      use Assent.TestCase

      import unquote(__MODULE__)
    end
  end

  alias Plug.Conn

  @spec expect_oauth2_access_token_request(Keyword.t(), function() | nil) :: :ok
  def expect_oauth2_access_token_request(opts \\ [], assert_fn \\ nil) do
    access_token = Keyword.get(opts, :access_token, "access_token")
    token_params = Keyword.get(opts, :params, %{access_token: access_token})
    uri = Keyword.get(opts, :uri, "/oauth/token")
    status_code = Keyword.get(opts, :status_code, 200)

    TestServer.add(uri,
      via: :post,
      to: fn conn ->
        {:ok, body, _conn} = Plug.Conn.read_body(conn, [])
        params = URI.decode_query(body)

        if assert_fn, do: assert_fn.(conn, params)

        send_json_resp(conn, token_params, status_code)
      end
    )
  end

  @spec expect_oauth2_user_request(map(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth2_user_request(user_params, opts \\ [], assert_fn \\ nil) do
    uri = Keyword.get(opts, :uri, "/api/user")

    expect_oauth2_api_request(uri, user_params, opts, assert_fn)
  end

  @spec expect_oauth2_api_request(binary(), map(), Keyword.t(), function() | nil) :: :ok
  def expect_oauth2_api_request(uri, response, opts \\ [], assert_fn \\ nil, method \\ :get) do
    access_token = Keyword.get(opts, :access_token, "access_token")
    status_code = Keyword.get(opts, :status_code, 200)

    TestServer.add(uri,
      via: method,
      to: fn conn ->
        if assert_fn, do: assert_fn.(conn)

        assert_bearer_token_in_header(conn, access_token)

        send_json_resp(conn, response, status_code)
      end
    )
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
    |> Conn.send_resp(status_code, @json_library.encode!(body))
  end
end
