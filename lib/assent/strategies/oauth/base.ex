defmodule Assent.Strategy.OAuth.Base do
  @moduledoc """
  OAuth 1.0 strategy base.

  ## Usage

      defmodule MyApp.MyOAuthStratey do
        use Assent.Strategy.OAuth

        @impl true
        def default_config(_config) do
          [
            site: "https://api.example.com",
            authorize_url: "/authorization/new",
            access_token_url: "/authorization/access_token"
            request_token_url: "/authorization/request_token",
            user_url: "/authorization.json",
            authorization_params: [scope: "default"]
          ]
        end

        @impl true
        def normalize(_config, user) do
          {:ok, %{
            "sub"   => user["id"],
            "name"  => user["name"],
            "email" => user["email"]
          }}
        end
      end
  """
  alias Assent.Strategy, as: Helpers
  alias Assent.Strategy.OAuth

  @callback default_config(Keyword.t()) :: Keyword.t()
  @callback normalize(Keyword.t(), map()) :: {:ok, map()} | {:ok, map(), map()} | {:error, term()}
  @callback get_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}

  @doc false
  defmacro __using__(_opts) do
    quote do
      @behaviour unquote(__MODULE__)

      alias Assent.Strategy, as: Helpers

      def authorize_url(config), do: unquote(__MODULE__).authorize_url(config, __MODULE__)

      def callback(config, params), do: unquote(__MODULE__).callback(config, params, __MODULE__)

      def get_user(config, token), do: OAuth.get_user(config, token)

      defoverridable unquote(__MODULE__)
    end
  end


  @spec authorize_url(Keyword.t(), module()) :: {:ok, %{url: binary()}} | {:error, term()}
  def authorize_url(config, strategy) do
    config
    |> set_config(strategy)
    |> OAuth.authorize_url()
  end

  @spec callback(Keyword.t(), map(), module()) :: {:ok, %{user: map()}} | {:error, term()}
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
