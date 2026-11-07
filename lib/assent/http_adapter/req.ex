if Code.ensure_loaded?(Req) do
  defmodule Assent.HTTPAdapter.Req do
    @moduledoc """
    HTTP adapter module for making http requests with Req.

    You can also override the Req options by updating the configuration:

        http_adapter: {Assent.HTTPAdapter.Req, [...]}

    Redirects are not followed by default, so credentials in headers and the
    request body are never sent to another URL. You can enable them with
    `:redirect`:

        http_adapter: {Assent.HTTPAdapter.Req, redirect: true}

    See `Assent.HTTPAdapter` for more.
    """
    alias Assent.{HTTPAdapter, HTTPAdapter.HTTPResponse}

    @behaviour HTTPAdapter

    @impl HTTPAdapter
    def request(method, url, body, headers, opts) do
      headers = headers ++ [HTTPAdapter.user_agent_header()]

      opts =
        Keyword.merge(
          [
            method: method,
            url: url,
            headers: headers,
            body: body,
            redirect: false
          ],
          opts
        )

      opts
      |> Req.new()
      |> Req.request()
      |> case do
        {:ok, response} ->
          headers = for {key, values} <- response.headers, value <- values, do: {key, value}

          {:ok, %HTTPResponse{status: response.status, headers: headers, body: response.body}}

        {:error, error} ->
          {:error, error}
      end
    end
  end
end
