defmodule Assent.Strategy do
  @moduledoc """
  Used for creating strategies.

  ## Usage

  Set up `my_strategy.ex` the following way:

      defmodule MyStrategy do
        @behaviour Assent.Strategy

        alias Assent.Strategy, as: Helpers

        def authorize_url(config) do
          # Generate redirect URL

          {:ok, %{url: url, ...}}
        end

        def callback(config, params) do
          # Fetch user data

          user = Helpers.normalize_userinfo(userinfo)

          {:ok, %{user: user, ...}}
        end
      end
  """
  @callback authorize_url(Keyword.t()) ::
              {:ok, %{:url => binary(), optional(atom()) => any()}} | {:error, term()}
  @callback callback(Keyword.t(), map()) ::
              {:ok, %{:user => map(), optional(atom()) => any()}} | {:error, term()}

  @doc """
  Makes a HTTP request.

  See `Assent.HTTPAdapter.request/5`.
  """
  def http_request(method, url, body, headers, config) do
    opts = Keyword.take(config, [:http_adapter, :json_library])

    Assent.HTTPAdapter.request(method, url, body, headers, opts)
  end

  @doc """
  Decode a JSON string.

  ## Options

  - `:json_library` - The JSON library to use, see
    `Assent.json_library/1`
  """
  @spec decode_json(binary(), Keyword.t()) :: {:ok, term()} | {:error, term()}
  def decode_json(response, config), do: Assent.json_library(config).decode(response)

  @doc """
  Verifies a JSON Web Token.

  See `Assent.JWTAdapter.verify/3` for options.
  """
  @spec verify_jwt(binary(), binary() | map() | nil, Keyword.t()) ::
          {:ok, map()} | {:error, any()}
  def verify_jwt(token, secret, config),
    do: Assent.JWTAdapter.verify(token, secret, jwt_adapter_opts(config))

  defp jwt_adapter_opts(config),
    do: Keyword.take(config, [:json_library, :jwt_adapter, :private_key_id])

  @doc """
  Signs a JSON Web Token.

  See `Assent.JWTAdapter.sign/3` for options.
  """
  @spec sign_jwt(map(), binary(), binary(), Keyword.t()) :: {:ok, binary()} | {:error, term()}
  def sign_jwt(claims, alg, secret, config),
    do: Assent.JWTAdapter.sign(claims, alg, secret, jwt_adapter_opts(config))

  @doc """
  Generates a URL.
  """
  @spec to_url(binary(), binary(), Keyword.t()) :: binary()
  def to_url(base_url, uri, params \\ [])
  def to_url(base_url, uri, []), do: endpoint(base_url, uri)

  def to_url(base_url, uri, params), do: "#{endpoint(base_url, uri)}?#{encode_query(params)}"

  defp endpoint(base_url, "/" <> uri) do
    case :binary.last(base_url) do
      ?/ -> "#{base_url}#{uri}"
      _ -> "#{base_url}/#{uri}"
    end
  end

  defp endpoint(_base_url, uri), do: uri

  defp encode_query(enumerable) do
    enumerable
    |> Enum.map(&encode_pair(&1, ""))
    |> List.flatten()
    |> Enum.join("&")
  end

  defp encode_pair({key, value}, "") do
    key = encode_value(key)

    encode_pair(value, key)
  end

  defp encode_pair({key, value}, encoded_key) do
    encode_pair(value, "#{encoded_key}[#{encode_value(key)}]")
  end

  defp encode_pair([{_key, _value} | _rest] = values, encoded_key) do
    Enum.map(values, &encode_pair(&1, encoded_key))
  end

  defp encode_pair(values, encoded_key) when is_list(values) do
    Enum.map(values, &encode_pair(&1, "#{encoded_key}[]"))
  end

  defp encode_pair(value, encoded_key) do
    "#{encoded_key}=#{encode_value(value)}"
  end

  defp encode_value(value), do: URI.encode_www_form(Kernel.to_string(value))

  @doc """
  Normalize API user request response into standard claims.

  Based on https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1
  """
  @spec normalize_userinfo(map(), map()) :: {:ok, map()}
  def normalize_userinfo(claims, extra \\ %{}) do
    standard_claims =
      Map.take(
        claims,
        ~w(sub name given_name family_name middle_name nickname
         preferred_username profile picture website email email_verified
         gender birthdate zoneinfo locale phone_number phone_number_verified
         address updated_at)
      )

    {:ok, prune(Map.merge(extra, standard_claims))}
  end

  @doc """
  Recursively prunes map for nil values.
  """
  @spec prune(map()) :: map()
  def prune(map) do
    map
    |> Enum.map(fn {k, v} -> if is_map(v), do: {k, prune(v)}, else: {k, v} end)
    |> Enum.filter(fn {_, v} -> not is_nil(v) end)
    |> Enum.into(%{})
  end

  @doc false
  def __normalize__({:ok, %{user: user} = results}, config, strategy) do
    config
    |> strategy.normalize(user)
    |> case do
      {:ok, user} -> normalize_userinfo(user)
      {:ok, user, extra} -> normalize_userinfo(user, extra)
      {:error, error} -> {:error, error}
    end
    |> case do
      {:error, error} -> {:error, error}
      {:ok, user} -> {:ok, %{results | user: user}}
    end
  end

  def __normalize__({:error, error}, _config, _strategy), do: {:error, error}

  # TODO: Remove in 0.3
  @deprecated "Use http_request/4 instead"
  def request(method, url, body, headers, config),
    do: http_request(method, url, body, headers, config)

  # TODO: Remove in 0.3
  def decode_response({res, %Assent.HTTPAdapter.HTTPResponse{} = response}, config) do
    IO.warn("Passing {:ok | :error, response} to decode_response/2 is deprecated")

    case decode_response(response, config) do
      {:ok, body} -> {res, %{response | body: body}}
      {:error, error} -> {:error, error}
    end
  end

  # TODO: Remove in 0.3
  def decode_response({:error, error}, _config) do
    IO.warn("Passing {:error, error} to decode_response/2 is deprecated")

    {:error, error}
  end

  # TODO: Remove in 0.3
  @deprecated "Use Assent.HTTPAdapter.decode_response/2 instead"
  def decode_response(response, config), do: Assent.HTTPAdapter.decode_response(response, config)
end
