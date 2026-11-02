defmodule Assent.Strategy.OAuth2.Base do
  @moduledoc """
  OAuth 2.0 strategy base.

  ## Usage

      defmodule MyApp.MyOAuth2Strategy do
        use Assent.Strategy.OAuth2.Base

        @impl true
        def default_config(_config) do
          [
            base_url: "https://api.example.com",
            user_url: "/authorization.json"
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
  alias Assent.Strategy.OAuth2

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
      def fetch_user(config, token), do: OAuth2.fetch_user(config, token)

      defoverridable unquote(__MODULE__)
    end
  end

  @spec authorize_url(Keyword.t(), module()) :: OAuth2.on_authorize_url()
  def authorize_url(config, strategy) do
    config
    |> set_config(strategy)
    |> OAuth2.authorize_url()
  end

  @spec callback(Keyword.t(), map(), module()) :: OAuth2.on_callback()
  def callback(config, params, strategy) do
    config = set_config(config, strategy)

    config
    |> OAuth2.callback(params, strategy)
    |> Helpers.__normalize__(config, strategy)
  end

  defp set_config(config, strategy) do
    config
    |> strategy.default_config()
    |> Keyword.merge(config)
    |> Keyword.put(:strategy, strategy)
  end
end
