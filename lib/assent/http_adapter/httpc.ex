if Code.ensure_loaded?(:httpc) do
  defmodule Assent.HTTPAdapter.Httpc do
    @moduledoc """
    HTTP adapter module for making http requests with `:httpc`.

    SSL verification is enabled automatically when both
    [`:certifi`](https://hexdocs.pm/certifi/) and
    [`:ssl_verify_fun`](https://hex.pm/packages/ssl_verify_fun) are present at
    compile time. Add them to your dependencies in `mix.exs`:

        defp deps do
          [
            {:certifi, "~> 2.4"},
            {:ssl_verify_fun, "~> 1.1"}
          ]
        end

    If these dependencies are added after Assent has been compiled,
    recompile Assent to enable SSL verification support:

        mix deps.compile assent --force

    You can also override the `:httpc` options by updating the configuration:

        http_adapter: {Assent.HTTPAdapter.Httpc, [...]}

    See `Assent.HTTPAdapter` for more.
    """
    alias Assent.{HTTPAdapter, HTTPAdapter.HTTPResponse}

    @behaviour HTTPAdapter

    @impl HTTPAdapter
    def request(method, url, body, headers, httpc_opts \\ nil) do
      headers = headers ++ [HTTPAdapter.user_agent_header()]
      request = httpc_request(url, body, headers)
      opts = parse_httpc_ssl_opts(httpc_opts, url)

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
      headers =
        Enum.map(headers, fn {key, value} ->
          {String.downcase(to_string(key)), to_string(value)}
        end)

      body = IO.iodata_to_binary(body)

      {:ok, %HTTPResponse{status: status, headers: headers, body: body}}
    end

    defp format_response({:error, error}), do: {:error, error}

    defp parse_httpc_ssl_opts(nil, url), do: parse_httpc_ssl_opts([], url)

    defp parse_httpc_ssl_opts(opts, url) do
      uri = URI.parse(url)

      case uri.scheme do
        "https" ->
          ssl_opts =
            opts
            |> Keyword.get(:ssl, [])
            |> verify_fun_ssl_opts(uri)
            |> cacerts_ssl_opts()

          Keyword.put(opts, :ssl, ssl_opts)

        "http" ->
          opts
      end
    end

    defp verify_fun_ssl_opts(ssl_opts, uri) do
      case Keyword.has_key?(ssl_opts, :verify_fun) do
        true -> ssl_opts
        false -> default_verify_fun_ssl_opts(ssl_opts, uri)
      end
    end

    if Code.ensure_loaded?(:ssl_verify_hostname) do
      defp default_verify_fun_ssl_opts(ssl_opts, uri) do
        # This handles certificates for wildcard domain with SAN extension for
        # OTP >= 22
        hostname_match_check =
          try do
            [
              customize_hostname_check: [
                match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
              ]
            ]
          rescue
            _e in UndefinedFunctionError -> []
          end

        Keyword.merge(
          [
            verify: :verify_peer,
            depth: 99,
            verify_fun:
              {&:ssl_verify_hostname.verify_fun/3, check_hostname: to_charlist(uri.host)}
          ] ++ hostname_match_check,
          ssl_opts
        )
      end
    else
      defp default_verify_fun_ssl_opts(_ssl_opts, _uri) do
        raise """
        This request can NOT be verified for valid SSL certificate.

        Please add `:ssl_verify_fun` to your projects dependencies:

          {:ssl_verify_fun, "~> 1.1"}

        And recompile Assent:

          mix deps.compile assent --force

        Or specify the ssl options in the `:http_adapter` config option:

          config =
            [
              client_id: "REPLACE_WITH_CLIENT_ID",
              client_secret: "REPLACE_WITH_CLIENT_SECRET",
              http_adapter: {#{__MODULE__}, ssl: [verify_peer: :verify_peer, verify_fun: ...]}
            ]
        """
      end
    end

    defp cacerts_ssl_opts(ssl_opts) do
      case Keyword.has_key?(ssl_opts, :cacerts) || Keyword.has_key?(ssl_opts, :cacertfile) do
        true -> ssl_opts
        false -> default_cacerts_ssl_opts(ssl_opts)
      end
    end

    if Code.ensure_loaded?(:certifi) do
      defp default_cacerts_ssl_opts(ssl_opts) do
        ssl_opts ++ [cacerts: :certifi.cacerts()]
      end
    else
      defp default_cacerts_ssl_opts(_ssl_opts) do
        raise """
        This request requires a CA trust store.

        Please add `:certifi` to your projects dependencies:

          {:certifi, "~> 2.4"}

        And recompile Assent:

          mix deps.compile assent --force

        Or specify the ssl options in the `:http_adapter` config option:

          config =
            [
              client_id: "REPLACE_WITH_CLIENT_ID",
              client_secret: "REPLACE_WITH_CLIENT_SECRET",
              http_adapter: {#{__MODULE__}, ssl: [cacerts: ...]}
            ]
        """
      end
    end
  end
end
