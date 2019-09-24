defmodule Assent.Test.OAuthTestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  setup _context do
    params = %{"oauth_token" => "request_token", "oauth_verifier" => "verifier"}
    bypass = Bypass.open()
    config = [consumer_key: "key", consumer_secret: "secret", site: "http://localhost:#{bypass.port}", redirect_uri: "http://localhost:4000/auth/callback", session_params: %{oauth_token_secret: "request_token_secret"}]

    {:ok, callback_params: params, config: config, bypass: bypass}
  end

  using do
    quote do
      use ExUnit.Case

      import unquote(__MODULE__)
    end
  end

  alias Plug.Conn

  @spec expect_oauth_request_token_request(Bypass.t(), Keyword.t()) :: :ok
  def expect_oauth_request_token_request(bypass, opts \\ []) do
    status_code    = Keyword.get(opts, :status_code, 200)
    content_type   = Keyword.get(opts, :content_type, "application/x-www-form-urlencoded")
    params         = Keyword.get(opts, :params, %{oauth_token: "request_token", oauth_token_secret: "request_token_secret"})
    response       =
      case content_type do
        "application/x-www-form-urlencoded" -> URI.encode_query(params)
        "application/json"                  -> Jason.encode!(params)
        _any                                -> params
      end

    Bypass.expect_once(bypass, "POST", "/oauth/request_token", fn conn ->
      conn
      |> Conn.put_resp_content_type(content_type)
      |> Conn.resp(status_code, response)
    end)
  end

  @spec expect_oauth_access_token_request(Bypass.t(), Keyword.t()) :: :ok
  def expect_oauth_access_token_request(bypass, _opts \\ []) do
    Bypass.expect_once(bypass, "POST", "/oauth/access_token", fn conn ->
      cond do
        invalid_oauth_access_token_request_signature?(conn) ->
          conn
          |> Conn.put_resp_content_type("application/json")
          |> Conn.send_resp(500, Jason.encode!(%{error: "Invalid signature"}))

        invalid_verifier?(conn) ->
          conn
          |> Conn.put_resp_content_type("application/json")
          |> Conn.send_resp(500, Jason.encode!(%{error: "CSRF"}))

        true ->
          token = %{
            oauth_token: "7588892-kagSNqWge8gB1WwE3plnFsJHAZVfxWD7Vb57p0b4&",
            oauth_token_secret: "PbKfYqSryyeKDWz4ebtY3o5ogNLG11WJuZBc9fQrQo"
          }

          conn
          |> Conn.put_resp_content_type("application/x-www-form-urlencoded")
          |> Conn.resp(200, URI.encode_query(token))
      end
    end)
  end

  defp invalid_oauth_access_token_request_signature?(conn) do
    %{"oauth_nonce" => nonce,
      "oauth_timestamp" => timestamp,
      "oauth_signature" => signature} = parse_auth_header(conn)

    creds =
      OAuther.credentials([
        consumer_key: "key",
        consumer_secret: "secret",
        token: "request_token",
        token_secret: "request_token_secret"])

    params =
      [{"oauth_verifier", "verifier"}]
      |> OAuther.protocol_params(creds)
      |> Enum.map(fn
          {"oauth_nonce", _} -> {"oauth_nonce", URI.decode(nonce)}
          {"oauth_timestamp", _} -> {"oauth_timestamp", timestamp}
          any -> any
        end)

    expected = OAuther.signature("post", "http://localhost:#{conn.port}/oauth/access_token", params, creds)

    URI.decode(signature) != expected
  end

  defp invalid_verifier?(conn) do
    %{"oauth_verifier" => verifier} = parse_auth_header(conn)

    verifier != "verifier"
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
  def expect_oauth_user_request(bypass, user_params, opts \\ []) do
    uri          = Keyword.get(opts, :uri, "/api/user")
    status_code  = Keyword.get(opts, :status_code, 200)

    Bypass.expect_once(bypass, "GET", uri, fn conn ->
      conn
      |> Conn.put_resp_content_type("application/json")
      |> Conn.send_resp(status_code, Jason.encode!(user_params))
    end)
  end
end
