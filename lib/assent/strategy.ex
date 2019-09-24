defmodule Assent.Strategy do
  @moduledoc """
  Used for creating strategies.

  ## Usage

  Set up `my_strategy.ex` the following way:

      defmodule MyStrategy do
        @behaviour Assent.Strategy

        def authorize_url(config) do
          # Generate redirect URL

          {:ok, %{url: url, ...}}
        end

        def callback(config, params) do
          # Fetch user data

          {:ok, %{user: user, ...}}
        end
      end
  """
  alias Assent.{Config, HTTPResponse, RequestError}

  @callback authorize_url(Config.t()) :: {:ok, %{:url => binary(), optional(atom()) => any()}} | {:error, term()}
  @callback callback(Config.t(), map()) :: {:ok, %{:user => map(), optional(atom()) => any()}} | {:error, term()}

  @doc """
  Makes a HTTP request.
  """
  @spec request(atom(), binary(), binary() | nil, list(), Config.t()) :: {:ok, HTTPResponse.t()} | {:error, HTTPResponse.t()} | {:error, term()}
  def request(method, url, body, headers, config) do
    {http_adapter, opts} = fetch_http_adapter(config)

    method
    |> http_adapter.request(url, body, headers, opts)
    |> parse_status_response(http_adapter, url)
  end

  defp fetch_http_adapter(config) do
    case Config.get(config, :http_adapter, Assent.HTTPAdapter.Httpc) do
      {http_adapter, opts} -> {http_adapter, opts}
      http_adapter         -> {http_adapter, nil}
    end
  end

  defp parse_status_response({:ok, %{status: status} = resp}, _http_adapter, _url) when status in 200..399 do
    {:ok, resp}
  end
  defp parse_status_response({:ok, %{status: status} = resp}, _http_adapter, _url) when status in 400..599 do
    {:error, resp}
  end
  defp parse_status_response({:error, error}, http_adapter, url) do
    [url | _rest] = String.split(url, "?", parts: 2)

    {:error, RequestError.unreachable(http_adapter, url, error)}
  end

  @doc """
  Decodes a request response.
  """
  @spec decode_response({atom(), any()}, Config.t()) :: {atom(), any()}
  def decode_response({status, %{body: body, headers: headers} = resp}, config) do
    {status, %{resp | body: decode_body(headers, body, config)}}
  end
  def decode_response(any, _config), do: any

  defp decode_body(headers, body, config) do
    case List.keyfind(headers, "content-type", 0) do
      {"content-type", "application/json" <> _rest} ->
        decode_json!(body, config)
      {"content-type", "text/javascript" <> _rest} ->
        decode_json!(body, config)
      {"content-type", "application/x-www-form-urlencoded" <> _reset} ->
        URI.decode_query(body)
      _any ->
        body
      end
  end

  @doc """
  Recursively prunes map for nil values.
  """
  @spec prune(map) :: map
  def prune(map) do
    map
    |> Enum.map(fn {k, v} -> if is_map(v), do: {k, prune(v)}, else: {k, v} end)
    |> Enum.filter(fn {_, v} -> not is_nil(v) end)
    |> Enum.into(%{})
  end

  @doc """
  Decode a JSON response to a map
  """
  @spec decode_json!(binary(), Config.t()) :: map()
  def decode_json!(response, config) do
    json_library = Config.get(config, :json_library, default_json_library())
    json_library.decode!(response)
  end

  defp default_json_library do
    Application.get_env(:assent, :json_library) || Application.get_env(:phoenix, :json_library, Poison)
  end

  @doc """
  Generates a URL
  """
  @spec to_url(binary(), binary(), Keyword.t()) :: binary()
  def to_url(site, uri, params \\ [])
  def to_url(site, uri, []), do: endpoint(site, uri)
  def to_url(site, uri, params) do
    endpoint(site, uri) <> "?" <> URI.encode_query(params)
  end

  defp endpoint(site, <<"/"::utf8, _::binary>> = uri),
    do: site <> uri
  defp endpoint(_site, url),
    do: url
end
