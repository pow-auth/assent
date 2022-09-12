defmodule Assent.Test.OIDCTestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  alias Assent.Test.OAuth2TestCase
  alias Plug.Conn

  @private_key """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
    kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
    m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
    NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
    3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
    QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
    kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
    amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
    +bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
    D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
    0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
    lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
    hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
    bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
    +jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
    BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
    2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
    QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
    5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
    Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
    NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
    8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
    3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
    y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
    jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
    -----END RSA PRIVATE KEY-----
    """
  @public_key """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
    vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
    aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
    tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
    e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
    V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
    MwIDAQAB
    -----END PUBLIC KEY-----
    """
  @client_id "id"
  @client_secret "secret"
  @claims %{
    "sub" => "1",
    "aud" => @client_id,
    "exp" => 1_311_281_970,
    "iat" => 1_311_280_970
  }

  setup _tags do
    TestServer.start()

    params = %{"code" => "test_code_value", "state" => "test_state_value"}
    config = [
      client_id: @client_id,
      openid_configuration: %{
        "issuer" => "http://localhost",
        "authorization_endpoint" => TestServer.url("/oauth/authorize"),
        "token_endpoint" => TestServer.url("/oauth/token"),
        "userinfo_endpoint" => TestServer.url("/userinfo"),
        "jwks_uri" => TestServer.url("/jwks_uri.json")
      },
      client_secret: @client_secret,
      site: TestServer.url(),
      redirect_uri: "http://localhost:4000/auth/callback",
      session_params: %{state: "test_state_value"}]

    {:ok, callback_params: params, config: config}
  end

  using do
    quote do
      use ExUnit.Case

      import unquote(__MODULE__)
      import OAuth2TestCase, only: [expect_oauth2_user_request: 2, expect_oauth2_user_request: 3]
    end
  end

  @spec expect_openid_config_request(map()) :: :ok
  def expect_openid_config_request(openid_config, opts \\ []) do
    uri          = Keyword.get(opts, :uri, "/.well-known/openid-configuration")
    status_code  = Keyword.get(opts, :status_code, 200)

    TestServer.add(uri, via: :get, to: fn conn ->
      send_json_resp(conn, openid_config, status_code)
    end)
  end

  @spec expect_oidc_access_token_request(Keyword.t(), function() | nil) :: :ok
  def expect_oidc_access_token_request(opts \\ [], assert_fn \\ nil) do
    id_token = Keyword.get_lazy(opts, :id_token, fn ->
      opts
      |> Keyword.get(:id_token_opts, [])
      |> Keyword.put_new(:iss, TestServer.url())
      |> gen_id_token()
    end)

    params = Keyword.get(opts, :params, %{access_token: "access_token", id_token: id_token})

    opts =
      opts
      |> Keyword.drop([:id_token, :id_token_opts])
      |> Keyword.put(:params, params)

    OAuth2TestCase.expect_oauth2_access_token_request(opts, assert_fn)
  end

  @spec expect_oidc_jwks_uri_request(Keyword.t()) :: :ok
  def expect_oidc_jwks_uri_request(opts \\ []) do
    uri         = Keyword.get(opts, :uri, "/jwks_uri.json")
    keys        = opts[:keys] || gen_keys(opts)
    status_code = Keyword.get(opts, :status_code, 200)

    TestServer.add(uri, via: :get, to: fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(status_code, Jason.encode!(%{"keys" => keys}))
    end)

    keys
  end

  @spec expect_oidc_userinfo_request(map() | binary(), Keyword.t()) :: :ok
  def expect_oidc_userinfo_request(claims_or_jwt, opts \\ [])
  def expect_oidc_userinfo_request(claims, opts) when is_map(claims) do
    opts = Keyword.put_new(opts, :uri, "/userinfo")

    OAuth2TestCase.expect_oauth2_user_request(claims, opts)
  end
  def expect_oidc_userinfo_request(jwt, opts) when is_binary(jwt) do
    uri          = Keyword.get(opts, :uri, "/userinfo")
    access_token = Keyword.get(opts, :access_token, "access_token")
    status_code  = Keyword.get(opts, :status_code, 200)

    TestServer.add(uri, via: :get, to: fn conn ->
      assert {"authorization", "Bearer #{access_token}"} in conn.req_headers

      conn
      |> Conn.put_resp_content_type("application/jwt")
      |> Conn.send_resp(status_code, jwt)
    end)
  end

  defp gen_keys(opts) do
    {_, jwk_rsa} = JOSE.JWK.to_map(JOSE.JWK.from_pem(@public_key))

    case Keyword.get(opts, :count, 2) do
      0 -> []
      1 -> [jwk_rsa]
      c -> Enum.map(1..c, &Map.put(jwk_rsa, "kid", "key-#{&1}"))
    end
  end

  @spec gen_id_token(Keyword.t()) :: binary()
  def gen_id_token(opts \\ []) do
    iss    = Keyword.get(opts, :iss, "http://localhost")
    claims = Keyword.get(opts, :claims, %{})
    alg    = Keyword.get(opts, :alg, "RS256")

    claims =
      @claims
      |> Map.put("iss", iss)
      |> Map.put("exp", :os.system_time(:second) + 600)
      |> Map.put("iat", :os.system_time(:second))
      |> Map.merge(claims)

    claims = Map.drop(claims, Enum.filter(Map.keys(claims), &is_nil(claims[&1])))

    alg
    |> signed_jwt(claims, opts)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp signed_jwt("HS256", claims, _opts) do
    @client_secret
    |> JOSE.JWK.from_oct()
    |> JOSE.JWT.sign(%{"alg" => "HS256"}, claims)
  end
  defp signed_jwt("RS256", claims, opts) do
    @private_key
    |> JOSE.JWK.from_pem()
    |> JOSE.JWT.sign(add_kid(%{"alg" => "RS256"}, opts), claims)
  end
  defp signed_jwt("none", claims, _opts) do
    16
    |> JOSE.JWK.generate_key()
    |> JOSE.JWT.sign(%{"alg" => "none"}, claims)
  end

  defp add_kid(jws, opts) do
    case opts[:kid] do
      nil -> jws
      kid -> Map.put(jws, "kid", kid)
    end
  end

  defp send_json_resp(conn, body, status_code) do
    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(status_code, Jason.encode!(body))
  end
end
