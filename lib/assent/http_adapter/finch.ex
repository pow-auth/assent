if Code.ensure_loaded?(Finch) do
  defmodule Assent.HTTPAdapter.Finch do
    @moduledoc """
    HTTP adapter module for making http requests with Finch.

    The Finch adapter must be configured with the supervisor by passing it as an
    option:

        http_adapter: {Assent.HTTPAdapter.Finch, [supervisor: MyFinch]}

    See `Assent.HTTPAdapter` for more.
    """
    alias Assent.{HTTPAdapter, HTTPAdapter.HTTPResponse}

    @behaviour HTTPAdapter

    @impl HTTPAdapter
    def request(method, url, body, headers, finch_opts \\ nil) do
      headers = headers ++ [HTTPAdapter.user_agent_header()]
      opts = finch_opts || []

      supervisor =
        Keyword.get(opts, :supervisor) ||
          raise "Missing `:supervisor` option for the #{inspect(__MODULE__)} configuration"

      build_opts = Keyword.get(opts, :build, [])
      request_opts = Keyword.get(opts, :request, [])

      method
      |> Finch.build(url, headers, body, build_opts)
      |> Finch.request(supervisor, request_opts)
      |> case do
        {:ok, response} ->
          {:ok,
           %HTTPResponse{
             status: response.status,
             headers: response.headers,
             body: response.body
           }}

        {:error, error} ->
          {:error, error}
      end
    end
  end
end
