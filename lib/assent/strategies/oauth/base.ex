defmodule Assent.Strategy.OAuth.Base do
  @moduledoc """
  OAuth 1.0a strategy base.

  ## Usage

      defmodule MyApp.MyOAuthStrategy do
        use Assent.Strategy.OAuth.Base

        @impl true
        def default_config(_config) do
          [
            base_url: "https://api.example.com",
            authorize_url: "/authorization/new",
            access_token_url: "/authorization/access_token",
            request_token_url: "/authorization/request_token",
            user_url: "/authorization.json",
            authorization_params: [scope: "default"]
          ]
        end

        @impl true
        def normalize(_config, user) do
          {:ok,
            # Conformed to https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1
            %{
              "sub"   => user["id"],
              "name"  => user["name"],
              "email" => user["email"]
            # },
            # # Provider specific data not part of the standard claims spec
            # %{
            #  "https://example.com/bio" => user["bio"]
            }
          }
        end
      end
  """
  alias Assent.Strategy, as: Helpers
  alias Assent.Strategy.OAuth

  @doc "Returns config defaults that are merged with the caller's config."
  @callback default_config(Keyword.t()) :: Keyword.t()

  @doc "Normalizes a user response into standard claims with optional extra data."
  @callback normalize(Keyword.t(), map()) :: {:ok, map()} | {:ok, map(), map()} | {:error, term()}

  @doc "Fetches user data from the provider using the access token."
  @callback fetch_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}

  @doc false
  defmacro __using__(_opts) do
    quote do
      @behaviour Assent.Strategy
      @behaviour unquote(__MODULE__)

      alias Assent.Strategy, as: Helpers

      @doc "Generates the authorization URL."
      @spec authorize_url(Keyword.t()) ::
              {:ok, %{:url => binary(), optional(atom()) => any()}} | {:error, term()}
      @impl Assent.Strategy
      def authorize_url(config), do: unquote(__MODULE__).authorize_url(config, __MODULE__)

      @doc "Handles the callback and returns the user and token."
      @spec callback(Keyword.t(), map()) ::
              {:ok, %{:user => map(), optional(atom()) => any()}} | {:error, term()}
      @impl Assent.Strategy
      def callback(config, params), do: unquote(__MODULE__).callback(config, params, __MODULE__)

      @doc "Fetches user data using the access token."
      @spec fetch_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}
      @impl unquote(__MODULE__)
      def fetch_user(config, token), do: OAuth.fetch_user(config, token)

      defoverridable unquote(__MODULE__)
      defoverridable Assent.Strategy
    end
  end

  @spec authorize_url(Keyword.t(), module()) :: OAuth.on_authorize_url()
  def authorize_url(config, strategy) do
    config
    |> set_config(strategy)
    |> OAuth.authorize_url()
  end

  @spec callback(Keyword.t(), map(), module()) :: OAuth.on_callback()
  def callback(config, params, strategy) do
    config = set_config(config, strategy)

    config
    |> OAuth.callback(params, strategy)
    |> Helpers.__normalize__(config, strategy)
  end

  defp set_config(config, strategy) do
    config
    |> strategy.default_config()
    |> Keyword.merge(config)
    |> Keyword.put(:strategy, strategy)
  end
end
