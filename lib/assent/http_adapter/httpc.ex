if Code.ensure_loaded?(:httpc) do
  defmodule Assent.HTTPAdapter.Httpc do
    @moduledoc """
    HTTP adapter module for making http requests with `:httpc`.

    You can override the `:httpc` options by updating the configuration:

        http_adapter: {Assent.HTTPAdapter.Httpc, [...]}

    See `Assent.HTTPAdapter` for more.

    ## TLS

    By default, the `:ssl` options are:

        [
          cacerts: :public_key.cacerts_get(),
          customize_hostname_check: [
            match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
          ],
          verify: :verify_peer
        ]

    You can configure the `:ssl` options, which are merged on top of the
    defaults:

        http_adapter: {Assent.HTTPAdapter.Httpc, ssl: [cacertfile: ~c"/path/to/ca.pem"]}

    HTTPS requests configured with `verify: :verify_none` are rejected. You can
    pass in a custom `:verify_fun` to handle certificate verification manually:

        http_adapter: {Assent.HTTPAdapter.Httpc, ssl: [verify_fun: {&MyModule.verify_fun/3, nil}]}
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
          Keyword.put(opts, :ssl, ssl_opts(opts))

        "http" ->
          opts
      end
    end

    defp ssl_opts(opts) do
      [
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ],
        verify: :verify_peer
      ]
      |> Keyword.merge(Keyword.get(opts, :ssl, []))
      |> validate_verify_option!()
      |> put_cacerts()
    end

    defp validate_verify_option!(ssl_opts) do
      case Keyword.get(ssl_opts, :verify) do
        :verify_peer ->
          ssl_opts

        other ->
          raise ArgumentError,
                "expected `:verify` in `:ssl` options to be `:verify_peer`, got: #{inspect(other)}"
      end
    end

    defp put_cacerts(ssl_opts) do
      case Keyword.has_key?(ssl_opts, :cacerts) || Keyword.has_key?(ssl_opts, :cacertfile) do
        true -> ssl_opts
        false -> Keyword.put(ssl_opts, :cacerts, :public_key.cacerts_get())
      end
    end
  end
end
