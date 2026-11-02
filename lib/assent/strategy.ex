defmodule Assent.Strategy do
  @moduledoc """
  Used for creating strategies.

  ## Usage

  Set up `my_strategy.ex` the following way:

      defmodule MyStrategy do
        @behaviour Assent.Strategy

        alias Assent.Strategy, as: Helpers

        @impl Assent.Strategy
        def authorize_url(config) do
          # Generate redirect URL

          {:ok, %{url: url, ...}}
        end

        @impl Assent.Strategy
        def callback(config, params) do
          # Fetch user data

          case Helpers.normalize_userinfo(userinfo) do
            {:ok, user} -> {:ok, %{user: user}}
            {:error, error} -> {:error, error}
          end
        end
      end
  """
  alias Assent.{CastClaimsError, HTTPAdapter, HTTPAdapter.HTTPRequest, HTTPAdapter.HTTPResponse}

  @doc """
  Generates the URL that redirects the user to the authorization provider.
  """
  @callback authorize_url(Keyword.t()) ::
              {:ok, %{:url => binary(), optional(atom()) => any()}} | {:error, term()}

  @doc """
  Completes the authorization callback and returns the authenticated user.
  """
  @callback callback(Keyword.t(), map()) ::
              {:ok, %{:user => map(), optional(atom()) => any()}} | {:error, term()}

  @type claim_type :: :binary | :integer | :boolean | claim_types()
  @type claim_types :: %{optional(binary()) => claim_type()}

  @doc """
  Makes an HTTP request.

  ## Options

    * `:prepare_http_request` - an MFA tuple `{module, function, arguments}`.
      It is invoked before an HTTP request is sent. The request is prepended to
      the argument list.

  See `Assent.HTTPAdapter.request/2` for adapter options.
  """
  @spec http_request(
          HTTPAdapter.method(),
          binary(),
          HTTPAdapter.body(),
          HTTPAdapter.headers(),
          Keyword.t()
        ) :: {:ok, HTTPResponse.t()} | {:error, HTTPResponse.t()} | {:error, term()}
  def http_request(method, url, body, headers, config) do
    opts = Keyword.take(config, [:http_adapter, :json_library])

    %HTTPRequest{method: method, url: url, body: body, headers: headers}
    |> apply_prepare_http_request(Keyword.get(config, :prepare_http_request))
    |> HTTPAdapter.request(opts)
  end

  defp apply_prepare_http_request(request, nil), do: request

  defp apply_prepare_http_request(request, {module, function, args}) do
    case apply(module, function, [request | args]) do
      %HTTPRequest{} = request ->
        request

      _other ->
        function = "#{inspect(module)}.#{function}/#{length(args) + 1}"

        raise ArgumentError, "expected #{function} to return %#{inspect(HTTPRequest)}{}"
    end
  end

  @doc """
  Decodes a JSON string.

  ## Options

    * `:json_library` - the JSON library to use, see `Assent.json_library/1`
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

  ## Examples

      iex> Assent.Strategy.to_url("https://example.com", "/authorize")
      "https://example.com/authorize"

      iex> Assent.Strategy.to_url("https://example.com", "/authorize", response_type: "code")
      "https://example.com/authorize?response_type=code"
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

  @registered_claim_member_types %{
    "sub" => :binary,
    "name" => :binary,
    "given_name" => :binary,
    "family_name" => :binary,
    "middle_name" => :binary,
    "nickname" => :binary,
    "preferred_username" => :binary,
    "profile" => :binary,
    "picture" => :binary,
    "website" => :binary,
    "email" => :binary,
    "email_verified" => :boolean,
    "gender" => :binary,
    "birthdate" => :binary,
    "zoneinfo" => :binary,
    "locale" => :binary,
    "phone_number" => :binary,
    "phone_number_verified" => :boolean,
    "address" => %{
      "formatted" => :binary,
      "street_address" => :binary,
      "locality" => :binary,
      "region" => :binary,
      "postal_code" => :binary,
      "country" => :binary
    },
    "updated_at" => :integer
  }

  @doc """
  Normalizes API user request response into standard claims.

  The function will cast values to adhere to the following types:

  ```
  #{inspect(@registered_claim_member_types, pretty: true)}
  ```

  Returns `{:error, %Assent.CastClaimsError{}}` if any of the above types can't be cast.

  Based on the [OpenID Connect Core 1.0 standard
  claims](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1).

  ## Examples

      iex> Assent.Strategy.normalize_userinfo(%{"sub" => "123"}, %{"extra_claim" => "value"})
      {:ok, %{"extra_claim" => "value", "sub" => "123"}}
  """
  @spec normalize_userinfo(map(), map()) :: {:ok, map()} | {:error, CastClaimsError.t()}
  def normalize_userinfo(claims, extra \\ %{}) do
    case cast_claims(claims, @registered_claim_member_types) do
      {:ok, casted_claims} -> {:ok, deep_merge_claims(casted_claims, extra)}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Casts the given claims according to the provided claim types.

  The supported types are defined by `t:claim_type/0`. Integers can be cast to
  binaries, integer strings can be cast to integers, and `"true"` and `"false"`
  can be cast to booleans.

  Claims that are not present in the claim types or have `nil` values are
  discarded. `{:error, %Assent.CastClaimsError{}}` is returned if a claim cannot be cast.

  ## Examples

      iex> claims = %{"sub" => "123", "email_verified" => "invalid"}
      iex> claim_types = %{"sub" => :binary, "email_verified" => :boolean}
      iex> Assent.Strategy.cast_claims(claims, claim_types)
      {:error, %Assent.CastClaimsError{claims: claims, invalid_types: %{"email_verified" => :boolean}}}

      iex> claims = %{"sub" => "123", "email_verified" => "true"}
      iex> claim_types = %{"sub" => :binary, "email_verified" => :boolean}
      iex> Assent.Strategy.cast_claims(claims, claim_types)
      {:ok, %{"sub" => "123", "email_verified" => true}}
  """
  @spec cast_claims(map(), claim_types()) :: {:ok, map()} | {:error, CastClaimsError.t()}
  def cast_claims(claims, claim_types) do
    case do_cast_claims(claims, claim_types) do
      {casted_claims, nil} ->
        {:ok, casted_claims || %{}}

      {_claims, invalid_claims} ->
        {:error,
         CastClaimsError.exception(claims: claims, invalid_types: Enum.into(invalid_claims, %{}))}
    end
  end

  defp do_cast_claims(claims, claim_types) do
    {casted_claims, invalid_claims} =
      Enum.reduce(claim_types, {[], []}, fn {key, type}, acc ->
        cast_claim(key, type, Map.get(claims, key), acc)
      end)

    {
      (casted_claims != [] && Enum.into(casted_claims, %{})) || nil,
      (invalid_claims != [] && Enum.into(invalid_claims, %{})) || nil
    }
  end

  defp cast_claim(_key, _type, nil, acc), do: acc

  defp cast_claim(key, %{} = claim_types, %{} = claims, {casted_claims, invalid_claims}) do
    {casted_sub_claims, invalid_sub_claims} = do_cast_claims(claims, claim_types)

    {
      (casted_sub_claims && [{key, casted_sub_claims} | casted_claims]) || casted_claims,
      (invalid_sub_claims && [{key, invalid_sub_claims} | invalid_claims]) || invalid_claims
    }
  end

  defp cast_claim(key, %{}, _value, {casted_claims, invalid_claims}) do
    {casted_claims, [{key, :map} | invalid_claims]}
  end

  defp cast_claim(key, type, value, {casted_claims, invalid_claims}) do
    case cast_value(value, type) do
      {:ok, value} -> {[{key, value} | casted_claims], invalid_claims}
      :error -> {casted_claims, [{key, type} | invalid_claims]}
    end
  end

  defp cast_value(value, :binary) when is_binary(value), do: {:ok, value}
  defp cast_value(value, :binary) when is_integer(value), do: {:ok, to_string(value)}
  defp cast_value(value, :integer) when is_integer(value), do: {:ok, value}
  defp cast_value(value, :integer) when is_binary(value), do: cast_integer(value)
  defp cast_value(value, :boolean) when is_boolean(value), do: {:ok, value}
  defp cast_value("true", :boolean), do: {:ok, true}
  defp cast_value("false", :boolean), do: {:ok, false}
  defp cast_value(_value, _type), do: :error

  defp cast_integer(value) do
    case Integer.parse(value) do
      {integer, ""} -> {:ok, integer}
      _ -> :error
    end
  end

  defp deep_merge_claims(claims, extra) do
    Enum.reduce(extra, claims, fn
      {_key, nil}, claims -> claims
      {key, value}, claims -> deep_merge_claim(claims, key, value, Map.get(claims, key))
    end)
  end

  defp deep_merge_claim(claims, key, sub_extra, nil), do: Map.put(claims, key, sub_extra)

  defp deep_merge_claim(claims, key, %{} = sub_extra, %{} = sub_claims) do
    Map.put(claims, key, deep_merge_claims(sub_claims, sub_extra))
  end

  defp deep_merge_claim(claims, _key, _sub_extra, _value), do: claims

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
end
