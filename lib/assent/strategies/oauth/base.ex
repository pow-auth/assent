defmodule Assent.Strategy.OAuth.Base do
  @moduledoc """
  OAuth 1.0 strategy base.

  ## Usage

      defmodule MyApp.MyOAuthStratey do
        use Assent.Strategy.OAuth

        @impl true
        def default_config(_config) do
          [
            base_url: "https://api.example.com",
            authorize_url: "/authorization/new",
            access_token_url: "/authorization/access_token"
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
      def fetch_user(config, token), do: OAuth.fetch_user(config, token)

      defoverridable unquote(__MODULE__)
      defoverridable Assent.Strategy
    end
  end

  @spec authorize_url(Keyword.t(), module()) :: {:ok, %{url: binary()}} | {:error, term()}
  def authorize_url(config, strategy) do
    config
    |> set_config(strategy)
    |> OAuth.authorize_url()
  end

  @spec callback(Keyword.t(), map(), module()) ::
          {:ok, %{user: map(), token: map()}} | {:error, term()}
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
