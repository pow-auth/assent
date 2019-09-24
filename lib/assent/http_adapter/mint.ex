defmodule Assent.HTTPAdapter.Mint do
  @moduledoc """
  HTTP adapter module for making http requests with Mint.

  Mint can be configured by updating the configuration to
  `http_adapter: {HTTPAdapter.Mint, [...]}`.
  """
  alias Assent.{HTTPAdapter, HTTPAdapter.HTTPResponse}

  @behaviour HTTPAdapter

  @impl HTTPAdapter
  def request(method, url, body, headers, mint_opts \\ nil) do
    headers = headers ++ [HTTPAdapter.user_agent_header()]

    %{scheme: scheme, port: port, host: host, path: path} = URI.parse(url)

    scheme
    |> open_mint_conn(host, port, mint_opts)
    |> mint_request(method, path, headers, body)
    |> format_response()
  end

  defp open_mint_conn(scheme, host, port, nil), do: open_mint_conn(scheme, host, port, [])
  defp open_mint_conn("http", host, port, opts), do: open_mint_conn(:http, host, port, opts)
  defp open_mint_conn("https", host, port, opts), do: open_mint_conn(:https, host, port, opts)
  defp open_mint_conn(scheme, host, port, opts) when is_atom(scheme), do: Mint.HTTP.connect(scheme, host, port, opts)

  defp mint_request(resp, :get, path, headers, body), do: mint_request(resp, "GET", path, headers, body)
  defp mint_request(resp, :post, path, headers, body), do: mint_request(resp, "POST", path, headers, body)
  defp mint_request(resp, method, nil, headers, body), do: mint_request(resp, method, "/", headers, body)
  defp mint_request({:ok, conn}, method, path, headers, body) do
    conn
    |> Mint.HTTP.request(method, path, headers, body)
    |> await_response()
  end
  defp mint_request({:error, error}, _method, _path, _headers, _body), do: {:error, error}

  defp await_response({:ok, conn, request_ref}), do: await_response(conn, request_ref)
  defp await_response(conn, request_ref, timeout \\ 5_000) do
    receive do
      message -> mint_stream(conn, request_ref, message)
    after timeout ->
      {:error, :timeout}
    end
  end

  defp mint_stream(conn, _request_ref, message) do
    case Mint.HTTP.stream(conn, message) do
      {:ok, _conn, responses} -> {:ok, responses}
      :unknown -> {:error, :unknown}
    end
  end

  defp format_response({:ok, responses}) do
    [{:status, _, status}, {:headers, _, headers} | responses] = responses
    body = merge_body(responses)

    {:ok, %HTTPResponse{status: status, headers: headers, body: body}}
  end
  defp format_response({:error, response}), do: {:error, response}

  defp merge_body([{:data, _request, new_body} | rest], body), do: merge_body(rest, body <> new_body)
  defp merge_body(_rest, body), do: body
  defp merge_body([{:data, _request, _body} | _rest] = responses), do: merge_body(responses, "")
end
