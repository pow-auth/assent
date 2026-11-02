defmodule Assent.Strategy.OIDC.Base do
  @moduledoc """
  OpenID Connect strategy base.

  ## Usage

      defmodule MyApp.MyOIDCStrategy do
        use Assent.Strategy.OIDC.Base

        @impl true
        def default_config(_config) do
          [
            base_url: "https://oidc.example.com"
          ]
        end

        @impl true
        def normalize(_config, user), do: {:ok, user}
      end
  """
  alias Assent.Strategy, as: Helpers
  alias Assent.Strategy.OIDC

  @doc "Returns config defaults that are merged with the caller's config."
  @callback default_config(Keyword.t()) :: Keyword.t()

  @doc "Normalizes a user response into standard claims with optional extra data."
  @callback normalize(Keyword.t(), map()) :: {:ok, map()} | {:ok, map(), map()} | {:error, term()}

  @doc "Fetches user data from the OpenID Connect ID token or UserInfo endpoint."
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

      @doc "Fetches user data from the ID token or UserInfo endpoint."
      @spec fetch_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}
      @impl unquote(__MODULE__)
      def fetch_user(config, token), do: OIDC.fetch_user(config, token)

      @doc "Returns the user claims without provider-specific normalization."
      @impl unquote(__MODULE__)
      def normalize(_config, user), do: {:ok, user, user}

      defoverridable unquote(__MODULE__)
      defoverridable Assent.Strategy
    end
  end

  @spec authorize_url(Keyword.t(), module()) :: OIDC.on_authorize_url()
  def authorize_url(config, strategy) do
    config
    |> set_config(strategy)
    |> OIDC.authorize_url()
  end

  @spec callback(Keyword.t(), map(), module()) :: OIDC.on_callback()
  def callback(config, params, strategy) do
    config = set_config(config, strategy)

    config
    |> OIDC.callback(params, strategy)
    |> Helpers.__normalize__(config, strategy)
  end

  defp set_config(config, strategy) do
    config
    |> strategy.default_config()
    |> Keyword.merge(config)
    |> Keyword.put(:strategy, strategy)
  end
end
