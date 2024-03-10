# Assent

[![Github CI](https://github.com/pow-auth/assent/workflows/CI/badge.svg)](https://github.com/pow-auth/assent/actions?query=workflow%3ACI)
[![hexdocs.pm](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/assent)
[![hex.pm](https://img.shields.io/hexpm/v/assent.svg?style=flat)](https://hex.pm/packages/assent)

Multi-provider authentication framework.

## Features

* Includes the following base strategies:
  * OAuth 1.0 - `Assent.Strategy.OAuth`
  * OAuth 2.0 - `Assent.Strategy.OAuth2`
  * OpenID Connect - `Assent.Strategy.OIDC`
* Includes the following provider strategies:
  * Apple Sign In - `Assent.Strategy.Apple`
  * Auth0 - `Assent.Strategy.Auth0`
  * Azure AD - `Assent.Strategy.AzureAD`
  * Basecamp - `Assent.Strategy.Basecamp`
  * DigitalOcean - `Assent.Strategy.DigitalOcean`
  * Discord - `Assent.Strategy.Discord`
  * Facebook - `Assent.Strategy.Facebook`
  * Github - `Assent.Strategy.Github`
  * Gitlab - `Assent.Strategy.Gitlab`
  * Google - `Assent.Strategy.Google`
  * Instagram - `Assent.Strategy.Instagram`
  * LINE Login - `Assent.Strategy.LINE`
  * Linkedin - `Assent.Strategy.Linkedin`
  * Spotify - `Assent.Strategy.Spotify`
  * Strava - `Assent.Strategy.Strava`
  * Slack - `Assent.Strategy.Slack`
  * Stripe Connect - `Assent.Strategy.Stripe`
  * Twitter - `Assent.Strategy.Twitter`
  * VK - `Assent.Strategy.VK`

## Installation

Add Assent to your list of dependencies in `mix.exs`:

```elixir
defp deps do
  [
    # ...
    {:assent, "~> 0.2.9"}
  ]
end
```

Run `mix deps.get` to install it.

#### HTTP client installation

By default, `Req` is used if you have it in your dependency list. If not, Erlang's `:httpc` will be used instead.

If you are using `:httpc` you should add the following dependencies to enable SSL validation:

```elixir
defp deps do
  [
    # ...
    # Required for SSL validation when using the `:httpc` adapter
    {:certifi, "~> 2.4"},
    {:ssl_verify_fun, "~> 1.1"}
  ]
end
```

You must also add `:inets` to `:extra_applications` in `mix.exs`:

```elixir
def application do
  [
    # ...
    extra_applications: [
      # ...
      :inets
    ]
  ]
end
```

This is not necessary if you use another HTTP adapter like `Req` or `Finch`.

## Getting started

A strategy consists of two phases; request and callback. In the request phase, the user would normally be redirected to the provider for authentication and then returned to initiate the callback phase.

### Single provider example

```elixir
defmodule ProviderAuth do
  import Plug.Conn

  alias Assent.{Config, Strategy.Github}

  @config [
    client_id: "REPLACE_WITH_CLIENT_ID",
    client_secret: "REPLACE_WITH_CLIENT_SECRET",
    redirect_uri: "http://localhost:4000/auth/github/callback"
  ]

  # http://localhost:4000/auth/github
  def request(conn) do
    @config
    |> Github.authorize_url()
    |> case do
      {:ok, %{url: url, session_params: session_params}} ->
        # Session params (used for OAuth 2.0 and OIDC strategies) will be
        # retrieved when user returns for the callback phase
        conn = put_session(conn, :session_params, session_params)

        # Redirect end-user to Github to authorize access to their account
        conn
        |> put_resp_header("location", url)
        |> send_resp(302, "")

      {:error, error} ->
        # Something went wrong generating the request authorization url
    end
  end

  # http://localhost:4000/auth/github/callback
  def callback(conn) do
    # End-user will return to the callback URL with params attached to the
    # request. These must be passed on to the strategy. In this example we only
    # expect GET query params, but the provider could also return the user with
    # a POST request where the params is in the POST body.
    %{params: params} = fetch_query_params(conn)

    # The session params (used for OAuth 2.0 and OIDC strategies) stored in the
    # request phase will be used in the callback phase
    session_params = get_session(conn, :session_params)

    @config
    # Session params should be added to the config so the strategy can use them
    |> Config.put(:session_params, session_params)
    |> Github.callback(params)
    |> case do
      {:ok, %{user: user, token: token}} ->
        # Authorization succesful

      {:error, error} ->
        # Authorizaiton failed
    end
  end
end
```

### Multi-provider example

This is a generalized flow that's similar to what's used in [PowAssent](https://github.com/danschultzer/pow_assent).

```elixir
config :my_app, :strategies,
  github: [
    client_id: "REPLACE_WITH_CLIENT_ID",
    client_secret: "REPLACE_WITH_CLIENT_SECRET",
    strategy: Assent.Strategy.Github
  ],
  # ...
```

```elixir
defmodule MultiProviderAuth do
  alias Assent.Config

  @spec request(atom()) :: {:ok, map()} | {:error, term()}
  def request(provider) do
    config = config!(provider)

    config[:strategy].authorize_url()
  end

  @spec callback(atom(), map(), map()) :: {:ok, map()} | {:error, term()}
  def callback(provider, params, session_params) do
    config = config!(provider)

    config
    |> Assent.Config.put(:session_params, session_params)
    |> config[:strategy].callback(params)
  end

  defp config!(provider) do
    config =
      Application.get_env(:my_app, :strategies)[provider] ||
        raise "No provider configuration for #{provider}"
    
    Config.put(config, :redirect_uri, "http://localhost:4000/oauth/#{provider}/callback")
  end
end
```

## Custom provider

You can create custom strategies. Here's an example of an OAuth 2.0 implementation using `Assent.Strategy.OAuth2.Base`:

```elixir
defmodule TestProvider do
  use Assent.Strategy.OAuth2.Base

  @impl true
  def default_config(_config) do
    [
      # `:base_url` will be used for any paths below
      base_url: "http://localhost:4000/api/v1",
       # Definining an absolute URI overrides the `:base_url`
      authorize_url: "http://localhost:4000/oauth/authorize",
      token_url: "/oauth/access_token",
      user_url: "/user",
      authorization_params: [scope: "email profile"],
      auth_method: :client_secret_post
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok,
      # Conformed to https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1
      %{
        "sub"      => user["sub"],
        "name"     => user["name"],
        "nickname" => user["username"],
        "email"    => user["email"]
      # },
      # # Provider specific data not part of the standard claims spec
      # %{
      #   "http://localhost:4000/bio" => user["bio"]
      }
    }
  end
end
```

The normalized user map should conform to the [OpenID Connect Core 1.0 Standard Claims spec](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1), and should return either `{:ok, userinfo_claims}` or `{:ok, userinfo_claims, additional}`. Any keys defined in the userinfo claims that aren't part of the specs will not be included in the user map. Instead, they should be set in the additional data that will then be merged on top of the userinfo claims excluding any keys that have already been set.

You can use any of the `Assent.Strategy.OAuth2.Base`, `Assent.Strategy.OAuth.Base`, and `Assent.Strategy.OIDC.Base` macros to set up the strategy.

If you need more control over the strategy than what the macros give you, you can implement your provider using the `Assent.Strategy` behaviour:

```elixir
defmodule TestProvider do
  @behaviour Assent.Strategy

  @spec authorize_url(Keyword.t()) :: {:ok, %{url: binary()}} | {:error, term()}
  def authorize_url(config) do
    # Generate authorization url
  end

  @spec callback(Keyword.t(), map()) :: {:ok, %{user: map(), token: map()}} | {:error, term()}
  def callback(config, params) do
    # Handle callback response
  end
end
```

## HTTP Client

Assent supports [`Req`](https://github.com/wojtekmach/req), [`Finch`](https://github.com/sneako/finch), and [`:httpc`](https://www.erlang.org/doc/man/httpc.html) out of the box. The `Req` HTTP client adapter will be used by default if enabled, otherwise Erlang's `:httpc` adapter will be included.

You can explicitly set the HTTP client adapter in the configuration:

```elixir
config = [
  client_id: "REPLACE_WITH_CLIENT_ID",
  client_secret: "REPLACE_WITH_CLIENT_SECRET",
  http_adapter: Assent.HTTPAdapter.Httpc
]
```

Or globally in the config:

```elixir
config :assent, http_adapter: Assent.HTTPAdapter.Httpc
```

### `Req`

Req doesn't require any additional configuration and will work out of the box:

```elixir
defp deps do
  [
    # ...
    {:req, "~> 0.4"}
  ]
end
```

### `:httpc`

If `Req` is not available, Erlangs built-in `:httpc` is used for requests. SSL verification is automatically enabled when `:certifi` and `:ssl_verify_fun` packages are available. `:httpc` only supports HTTP/1.1.

```elixir
defp deps do
  [
    # ...
    # Required for SSL validation if using the `:httpc` adapter
    {:certifi, "~> 2.4"},
    {:ssl_verify_fun, "~> 1.1"}
  ]
end
```

You must include `:inets` to `:extra_applications` to include `:httpc` in your release.

### Finch

Finch will require a supervisor in your application.

Update `mix.exs`:

```elixir
defp deps do
  [
    # ...
    {:finch, "~> 0.16"}
  ]
end
```

Ensure you start the Finch supervisor in your application, and set `:http_adapter` in your provider configuration using your connection pool:

```elixir
config = [
  client_id: "REPLACE_WITH_CLIENT_ID",
  client_secret: "REPLACE_WITH_CLIENT_SECRET",
  http_adapter: {Assent.HTTPAdapter.Finch, supervisor: MyFinch}
]
```

## JWT Adapter

By default the built-in `Assent.JWTAdapter.AssentJWT` is used for JWT parsing, but you can change it to any third-party library with a custom `Assent.JWTAdapter`. A [JOSE](https://github.com/potatosalad/erlang-jose) adapter `Assent.JWTAdapter.JOSE` is included.

To use JOSE, update `mix.exs`:

```elixir
defp deps do
  [
    # ...
    {:jose, "~> 1.8"}
  ]
end
```

And pass the `:jwt_adapter` with your provider configuration:

```elixir
config = [
  client_id: "REPLACE_WITH_CLIENT_ID",
  client_secret: "REPLACE_WITH_CLIENT_SECRET",
  jwt_adapter: Assent.JWTAdapter.JOSE
]
```

Or globally in the config:

```elixir
config :assent, jwt_adapter: AssAssent.JWTAdapter.JOSE
```

## LICENSE

(The MIT License)

Copyright (c) 2019-present Dan Schultzer & the Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
