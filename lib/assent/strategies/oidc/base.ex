defmodule Assent.Strategy.OIDC.Base do
  @moduledoc """
  OIDC OAuth 2.0 strategy base.

  ## Usage

      defmodule MyApp.MyOIDCStrategy do
        use Assent.Strategy.OIDC.Base

        def default_config(_config) do
          [
            base_url: "https://oidc.example.com"
          ]
        end

        def normalize(_config, user), do: {:ok, user}
      end
  """
  alias Assent.Strategy, as: Helpers
  alias Assent.Strategy.OIDC

  @callback default_config(Keyword.t()) :: Keyword.t()
  @callback normalize(Keyword.t(), map()) :: {:ok, map()} | {:ok, map(), map()} | {:error, term()}
  @callback fetch_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}

  @doc false
  defmacro __using__(_opts) do
    quote do
      @behaviour Assent.Strategy
      @behaviour unquote(__MODULE__)

      alias Assent.Strategy, as: Helpers

      @impl Assent.Strategy
      def authorize_url(config), do: unquote(__MODULE__).authorize_url(config, __MODULE__)

      @impl Assent.Strategy
      def callback(config, params), do: unquote(__MODULE__).callback(config, params, __MODULE__)

      @impl unquote(__MODULE__)
      def fetch_user(config, token), do: OIDC.fetch_user(config, token)

      @impl unquote(__MODULE__)
      def normalize(_config, user), do: {:ok, user, user}

      defoverridable unquote(__MODULE__)
      defoverridable Assent.Strategy
    end
  end

  @spec authorize_url(Keyword.t(), module()) ::
          {:ok,
           %{
             session_params: %{state: binary()} | %{state: binary(), nonce: binary()},
             url: binary()
           }}
          | {:error, term()}
  def authorize_url(config, strategy) do
    config
    |> set_config(strategy)
    |> OIDC.authorize_url()
  end

  @spec callback(Keyword.t(), map(), module()) ::
          {:ok, %{user: map(), token: map()}} | {:error, term()}
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
