defmodule Assent do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()
             |> String.split("<!-- MDOC !-->")
             |> Enum.fetch!(1)
             # Replace Markdown-linked HexDocs cross-references with plain
             # references so ExDoc can resolve links correctly.
             |> then(&Regex.replace(~r/\[(`[^`]+`)\]\([^)]+\)/, &1, "\\1"))

  defmodule MissingConfigError do
    @moduledoc """
    An exception for when a required configuration key is missing.

    ## Fields

      * `:key` - the missing configuration key
      * `:config` - the configuration passed to `Assent.fetch_config/2`

    ## Examples

        iex> {:error, error} = Assent.fetch_config([], :client_id)
        iex> Exception.message(error)
        "expected :client_id in config, got: []"
    """

    defexception [:key, :config]

    @type t :: %__MODULE__{
            key: atom(),
            config: Keyword.t()
          }

    def message(exception) do
      key = inspect(exception.key)
      config_keys = inspect(Keyword.keys(exception.config))

      "expected #{key} in config, got: #{config_keys}"
    end
  end

  defmodule CallbackError do
    @moduledoc """
    An exception for when an authorization provider reports a callback error.

    ## Fields

      * `:message` - a description of the error
      * `:error` - the provider's error code, if present
      * `:error_uri` - a URI with further information, if present
    """

    defexception [:message, :error, :error_uri]

    @type t :: %__MODULE__{
            message: binary(),
            error: binary() | nil,
            error_uri: binary() | nil
          }
  end

  defmodule CallbackCSRFError do
    @moduledoc """
    An exception for when callback CSRF validation fails.

    ## Fields

      * `:key` - the callback parameter that failed validation

    ## Examples

        iex> error = Assent.CallbackCSRFError.exception(key: "state")
        iex> Exception.message(error)
        "expected callback parameter `state` to match its value in session params"
    """

    defexception [:key]

    @type t :: %__MODULE__{
            key: binary()
          }

    def message(exception) do
      "expected callback parameter `#{exception.key}` to match its value in session params"
    end
  end

  defmodule MissingParamError do
    @moduledoc """
    An exception for when a required parameter is missing.

    ## Fields

      * `:key` - the missing parameter name
      * `:params` - the original parameters
      * `:context` - whether the parameters came from regular params or a token

    ## Examples

        iex> {:error, error} = Assent.fetch_token_param(%{"access_token" => "secret"}, "refresh_token")
        iex> Exception.message(error)
        "expected \\\"refresh_token\\\" in token, got: [\\\"access_token\\\"]"
    """

    defexception [:key, :params, context: :params]

    @type t :: %__MODULE__{
            key: binary(),
            params: map(),
            context: :params | :token
          }

    def message(exception) do
      key = inspect(exception.key)
      param_keys = exception.params |> Map.keys() |> Enum.sort() |> inspect()

      "expected #{key} in #{exception.context}, got: #{param_keys}"
    end
  end

  defmodule RequestError do
    @moduledoc """
    An exception for when a provider rejects an HTTP request.

    ## Fields

      * `:message` - a description of the error
      * `:response` - the normalized HTTP response

    ## Examples

        iex> response = %Assent.HTTPAdapter.HTTPResponse{
        ...>   http_adapter: Assent.HTTPAdapter.Httpc,
        ...>   request_url: "https://example.com/user?access_token=secret",
        ...>   status: 401,
        ...>   body: %{"error" => "invalid_token"}
        ...> }
        iex> error = Assent.RequestError.exception(message: "unauthorized token", response: response)
        iex> Exception.message(error)
        "unauthorized token\\n\\n" <>
          "HTTP Adapter: Assent.HTTPAdapter.Httpc\\n" <>
          "Request URL: https://example.com/user\\n\\n" <>
          "Response status: 401\\n\\n" <>
          "Response headers:\\n\\n\\n" <>
          "Response body:\\n%{\\\"error\\\" => \\\"invalid_token\\\"}\\n\\n"
    """

    defexception [:message, :response]

    alias Assent.HTTPAdapter

    @type t :: %__MODULE__{
            message: binary(),
            response: HTTPAdapter.HTTPResponse.t()
          }

    def message(exception) do
      """
      #{exception.message}

      #{HTTPAdapter.format_http_response(exception.response)}
      """
    end
  end

  defmodule InvalidResponseError do
    @moduledoc """
    An exception for when an HTTP response is invalid.

    ## Fields

      * `:response` - the normalized HTTP response
    """

    defexception [:response]

    alias Assent.HTTPAdapter

    @type t :: %__MODULE__{response: HTTPAdapter.HTTPResponse.t()}

    def message(exception) do
      """
      invalid response

      #{HTTPAdapter.format_http_response(exception.response)}
      """
    end
  end

  defmodule UnexpectedResponseError do
    @moduledoc """
    An exception for when an HTTP response is unexpected.

    ## Fields

      * `:response` - the normalized HTTP response
    """

    defexception [:response]

    alias Assent.HTTPAdapter

    @type t :: %__MODULE__{response: HTTPAdapter.HTTPResponse.t()}

    def message(exception) do
      """
      unexpected response

      #{HTTPAdapter.format_http_response(exception.response)}
      """
    end
  end

  defmodule ServerUnreachableError do
    @moduledoc """
    An exception for when a server is unreachable.

    ## Fields

      * `:http_adapter` - the HTTP adapter module
      * `:request_url` - the request URL
      * `:reason` - the underlying failure reason returned by the HTTP adapter

    ## Examples

        iex> error = Assent.ServerUnreachableError.exception(http_adapter: Assent.HTTPAdapter.Httpc, request_url: "https://example.com/user?access_token=secret", reason: :econnrefused)
        iex> Exception.message(error)
        "server is unreachable\\n\\n" <>
          "HTTP Adapter: Assent.HTTPAdapter.Httpc\\n" <>
          "Request URL: https://example.com/user\\n\\n" <>
          "Reason:\\n" <>
          ":econnrefused\\n"
    """

    defexception [:http_adapter, :request_url, :reason]

    @type t :: %__MODULE__{
            http_adapter: module(),
            request_url: binary(),
            reason: term()
          }

    def message(exception) do
      [url | _rest] = String.split(exception.request_url, "?", parts: 2)

      """
      server is unreachable

      HTTP Adapter: #{inspect(exception.http_adapter)}
      Request URL: #{url}

      Reason:
      #{inspect(exception.reason)}
      """
    end
  end

  defmodule CastClaimsError do
    @moduledoc """
    An exception for when claims cannot be cast to the requested types.

    ## Fields

      * `:claims` - the original claims
      * `:invalid_types` - the claim types for the claims that couldn't be cast

    ## Examples

        iex> {:error, error} = Assent.Strategy.cast_claims(%{"email_verified" => "sometimes"}, %{"email_verified" => :boolean})
        iex> Exception.message(error)
        "claims can't be cast\\n\\n" <>
          "The following claims did not match the expected types:\\n\\n" <>
          "- \\\"email_verified\\\" to :boolean\\n"
    """

    defexception [:claims, :invalid_types]

    @type t :: %__MODULE__{
            claims: map(),
            invalid_types: map()
          }

    def message(exception) do
      """
      claims can't be cast

      The following claims did not match the expected types:

      #{exception.invalid_types |> to_lines() |> Enum.join("\n")}
      """
    end

    defp to_lines(claim_types, prepend \\ "") do
      claim_types
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.reduce([], fn
        {key, %{} = claim_types}, acc ->
          acc ++ to_lines(claim_types, prepend <> "#{inspect(key)} -> ")

        {key, type}, acc ->
          acc ++ ["- #{prepend}#{inspect(key)} to #{inspect(type)}"]
      end)
    end
  end

  @doc """
  Fetches the key value from the configuration.

  Returns an `Assent.MissingConfigError` if the key is not found.
  """
  @spec fetch_config(Keyword.t(), atom()) :: {:ok, any()} | {:error, MissingConfigError.t()}
  def fetch_config(config, key) when is_list(config) and is_atom(key) do
    case Keyword.fetch(config, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, MissingConfigError.exception(key: key, config: config)}
    end
  end

  @doc """
  Fetches the key value from the params.

  Returns an `Assent.MissingParamError` if the key is not found.
  """
  @spec fetch_param(map(), binary()) :: {:ok, any()} | {:error, MissingParamError.t()}
  def fetch_param(params, key), do: do_fetch_param(params, key, :params)

  defp do_fetch_param(params, key, context) do
    case Map.fetch(params, key) do
      {:ok, value} ->
        {:ok, value}

      :error ->
        {:error, MissingParamError.exception(key: key, params: params, context: context)}
    end
  end

  @doc """
  Fetches the key value from the token.

  Returns an `Assent.MissingParamError` if the key is not found.
  """
  @spec fetch_token_param(map(), binary()) :: {:ok, any()} | {:error, MissingParamError.t()}
  def fetch_token_param(token, key), do: do_fetch_param(token, key, :token)

  @doc """
  Fetches the JSON library in config.

  If not found in provided config, this will attempt to load the JSON library
  from global application environment for `:assent`. Defaults to `JSON`.
  """
  @spec json_library(Keyword.t()) :: module()
  def json_library(config) do
    case Keyword.fetch(config, :json_library) do
      :error -> Application.get_env(:assent, :json_library, JSON)
      {:ok, json_library} -> json_library
    end
  end

  import Bitwise

  @doc false
  @spec constant_time_compare(binary(), binary()) :: boolean()
  def constant_time_compare(left, right) when is_binary(left) and is_binary(right) do
    byte_size(left) == byte_size(right) and constant_time_compare(left, right, 0)
  end

  defp constant_time_compare(<<x, left::binary>>, <<y, right::binary>>, acc) do
    xorred = bxor(x, y)
    constant_time_compare(left, right, acc ||| xorred)
  end

  defp constant_time_compare(<<>>, <<>>, acc) do
    acc === 0
  end
end
