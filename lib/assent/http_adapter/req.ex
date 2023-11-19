if Code.ensure_loaded?(Req) do
  defmodule Assent.HTTPAdapter.Req do
    @moduledoc """
    HTTP adapter module for making http requests with Req.

    You can also override the Req options by updating the configuration:

        http_adapter: {Assent.HTTPAdapter.Req, [...]}

    See `Assent.HTTPAdapter` for more.
    """
    alias Assent.{HTTPAdapter, HTTPAdapter.HTTPResponse}

    @behaviour HTTPAdapter

    @impl HTTPAdapter
    def request(method, url, body, headers, req_opts \\ nil) do
      headers = headers ++ [HTTPAdapter.user_agent_header()]
      opts = req_opts || []

      opts =
        Keyword.merge(
          [
            method: method,
            url: url,
            headers: headers,
            body: body
          ],
          opts
        )

      opts
      |> Req.new()
      |> Req.request()
      |> case do
        {:ok, response} ->
          headers =
            Enum.map(headers, fn {key, value} ->
              {String.downcase(to_string(key)), to_string(value)}
            end)

          {:ok, %HTTPResponse{status: response.status, headers: headers, body: response.body}}

        {:error, error} ->
          {:error, error}
      end
    end
  end
end
