# Assent

[![Build Status](https://travis-ci.org/pow-auth/assent.svg?branch=master)](https://travis-ci.org/pow-auth/assent) [![hex.pm](http://img.shields.io/hexpm/v/assent.svg?style=flat)](https://hex.pm/packages/assent)

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
  * Discord - `Assent.Strategy.Discord`
  * Facebook - `Assent.Strategy.Facebook`
  * Github - `Assent.Strategy.Github`
  * Gitlab - `Assent.Strategy.Gitlab`
  * Google - `Assent.Strategy.Google`
  * Instagram - `Assent.Strategy.Instagram`
  * Slack - `Assent.Strategy.Slack`
  * Twitter - `Assent.Strategy.Twitter`
  * VK - `Assent.Strategy.VK`

## Installation

Add Assent to your list of dependencies in `mix.exs`:

```elixir
defp deps do
  [
    # ...
    {:assent, "~> 0.1.0"},

    # Optional, but recommended for SSL validation with :httpc adapter
    {:certifi, "~> 2.4"},
    {:ssl_verify_fun, "~> 1.1"}
  ]
end
```

Run `mix deps.get` to install it.

## Getting started

A strategy consists of two phases; request and callback. In the request phase the user would normally be redirected to the provider for authentication. After authentication, the provider will be redirect the user back to the callback phase.

### Single provider example

```elixir
config = [
  client_id: "REPLACE_WITH_CLIENT_ID",
  client_secret: "REPLACE_WITH_CLIENT_SECRET",
  redirect_uri: "http://localhost:4000/oauth/callback"
]

# Redirect user to provider
{:ok, %{url: url, session_params: session_params}} = Assent.Strategy.Github.authorize_url(config)

# Handle callback
{:ok, %{user: user, token: token}} =
  config
  |> Assent.Config.put(:session_params, session_params)
  |> Assent.Strategy.Github.callback(params)
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
defmodule MultiProvider do
  @spec request(atom()) :: {:ok, map()} | {:error, term()}
  def request(provider) do
    config = config!(provider)

    config[:strategy].authorize_url(config)
  end

  @spec callback(atom(), map(), map()) :: {:ok, map()} | {:error, term()}
  def callback(provider, params, session_params \\ %{}) do
    config =
      provider
      |> config!()
      |> Assent.Config.put(:session_params, session_params)

    config[:strategy].callback(config, params)
  end

  defp config!(provider) do
    Application.get_env(:my_app, :strategies)[provider] || raise "No provider configuration for #{provider}"
  end
end
```

## Custom provider

You can add your own custom strategy.

Here's an example of an OAuth 2.0 implementation using `Assent.Strategy.OAuth2.Base`:

```elixir
defmodule TestProvider do
  use Assent.Strategy.OAuth2.Base

  @impl true
  def default_config(_config) do
    [
      site: "http://localhost:4000/",
      authorize_url: "http://localhost:4000/oauth/authorize",
      token_url: "http://localhost:4000/oauth/access_token",
      user_url: "/user",
      authorization_params: [scope: "email profile"]
    ]
  end

  @impl true
  def normalize(_config, user) do
    {:ok, %{
      "sub"   => user["sub"],
      "name"  => user["name"],
      "email" => user["email"]
    },
    %{
      "test_provider_bio" => user["bio"]
    }}
  end
end
```

The normalized user map should conform to the [OpenID Connect Core 1.0 Standard Claims spec](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1), and should return either `{:ok, userinfo_claims}` or `{:ok, userinfo_claims, additional}`.

You can also use `Assent.Strategy`:

```elixir
defmodule TestProvider do
  @behaviour Assent.Strategy

  @spec authorize_url(Keyword.t()) :: {:ok, %{url: binary()}} | {:error, term()}
  def authorize_url(config) do
    # Generate authorization url
  end

  @spec callback(Keyword.t(), map()) :: {:ok, %{user: map()}} | {:error, term()}
  def callback(config, params) do
    # Handle callback response
  end
end
```

## HTTP Adapter

By default Erlangs built-in `:httpc` is used for requests. SSL verification is automatically enabled when `:certifi` and `:ssl_verify_fun` packages are available. `:httpc` only supports HTTP/1.1.

If you would like HTTP/2 support, you should consider adding [`Mint`](https://github.com/ericmj/mint) to your project.

Update `mix.exs`:

```elixir
defp deps do
  [
    # ...
    {:mint, "~> 0.1.0"},
    {:castore, "~> 0.1.0"} # Required for SSL validation
  ]
end
```

Pass the `:http_adapter` with your provider configuration:

```elixir
config = [
  client_id: "REPLACE_WITH_CLIENT_ID",
  client_secret: "REPLACE_WITH_CLIENT_SECRET",
  http_adapter: Assent.HTTPAdapter.Mint
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

## LICENSE

(The MIT License)

Copyright (c) 2019 Dan Schultzer & the Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
