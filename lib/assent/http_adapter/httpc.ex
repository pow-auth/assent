if Code.ensure_loaded?(:httpc) do
  defmodule Assent.HTTPAdapter.Httpc do
    @moduledoc """
    HTTP adapter module for making http requests with `:httpc`.

    SSL verification is enabled automatically. You can override the `:ssl` options
    to use your own trust store or verify function:

        http_adapter: {Assent.HTTPAdapter.Httpc, ssl: [cacertfile: ~c"/path/to/ca.pem"]}

    SSL verification can be turned off with `verify: :verify_none`, HTTPS
    requests will then raise.

    You can also override the `:httpc` options by updating the configuration:

        http_adapter: {Assent.HTTPAdapter.Httpc, [...]}

    See `Assent.HTTPAdapter` for more.
    """
    alias Assent.{HTTPAdapter, HTTPAdapter.HTTPResponse}

    @behaviour HTTPAdapter

    @impl HTTPAdapter
    def request(method, url, body, headers, opts) do
      headers = headers ++ [HTTPAdapter.user_agent_header()]
      request = httpc_request(url, body, headers)
      opts = parse_httpc_ssl_opts(opts, url)

      method
      |> :httpc.request(request, opts, [])
      |> format_response()
    end

    defp httpc_request(url, body, headers) do
      url = to_charlist(url)
      headers = Enum.map(headers, fn {k, v} -> {to_charlist(k), to_charlist(v)} end)

      do_httpc_request(url, body, headers)
    end

    defp do_httpc_request(url, nil, headers) do
      {url, headers}
    end

    defp do_httpc_request(url, body, headers) do
      {content_type, headers} = split_content_type_headers(headers)
      body = to_charlist(body)
      headers = set_content_length_header(headers, body)

      {url, headers, content_type, body}
    end

    defp split_content_type_headers(headers) do
      case List.keytake(headers, ~c"content-type", 0) do
        nil -> {~c"text/plain", headers}
        {{_, ct}, headers} -> {ct, headers}
      end
    end

    defp set_content_length_header(headers, body) do
      case List.keyfind(headers, ~c"content-length", 0) do
        nil ->
          length = body |> IO.iodata_length() |> Integer.to_string()
          [{~c"content-length", length} | headers]

        _ ->
          headers
      end
    end

    defp format_response({:ok, {{_, status, _}, headers, body}}) do
      headers = for {key, value} <- headers, do: {to_string(key), to_string(value)}
      body = IO.iodata_to_binary(body)

      {:ok, %HTTPResponse{status: status, headers: headers, body: body}}
    end

    defp format_response({:error, error}), do: {:error, error}

    defp parse_httpc_ssl_opts(opts, url) do
      uri = URI.parse(url)

      case uri.scheme do
        "https" ->
          ssl_opts =
            opts
            |> Keyword.get(:ssl, [])
            |> verify_fun_ssl_opts()
            |> cacerts_ssl_opts()

          Keyword.put(opts, :ssl, ssl_opts)

        "http" ->
          opts
      end
    end

    defp verify_fun_ssl_opts(ssl_opts) do
      cond do
        ssl_opts[:verify] == :verify_none ->
          raise """
          This request can NOT be verified for valid SSL certificate.

          SSL verification has been turned off with `verify: :verify_none` in the ssl
          options of the `:http_adapter` config option, and HTTPS requests are never
          made without verification. Please remove it to verify with the operating
          system trust store, or specify your own verification in its place:

            config =
              [
                client_id: "REPLACE_WITH_CLIENT_ID",
                client_secret: "REPLACE_WITH_CLIENT_SECRET",
                http_adapter: {#{inspect(__MODULE__)}, ssl: [verify_fun: ...]}
              ]
          """

        Keyword.has_key?(ssl_opts, :verify_fun) ->
          ssl_opts

        true ->
          Keyword.merge(
            [
              customize_hostname_check: [
                match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
              ]
            ],
            ssl_opts
          )
      end
    end

    defp cacerts_ssl_opts(ssl_opts) do
      if Keyword.has_key?(ssl_opts, :cacerts) or Keyword.has_key?(ssl_opts, :cacertfile) do
        ssl_opts
      else
        ssl_opts ++ [cacerts: :public_key.cacerts_get()]
      end
    end
  end
end
