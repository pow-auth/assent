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

  ## Non-standard token responses

  Some providers wrap the token response in an envelope rather than returning
  the OAuth2-standard `{"access_token": ...}` object at the top level. Override
  `normalize_access_token/1` to reshape the decoded response body before it is
  processed:

      @impl true
      def normalize_access_token(%{"data" => token}), do: {:ok, token}
      def normalize_access_token(token), do: {:ok, token}

  It defaults to the identity function, so standard providers need not
  implement it.
  """
  alias Assent.Strategy, as: Helpers
  alias Assent.Strategy.OAuth2

  @callback default_config(Keyword.t()) :: Keyword.t()
  @callback normalize(Keyword.t(), map()) :: {:ok, map()} | {:ok, map(), map()} | {:error, term()}
  @callback fetch_user(Keyword.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback normalize_access_token(map()) :: {:ok, map()} | {:error, term()}

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
      def fetch_user(config, token), do: OAuth2.fetch_user(config, token)

      @impl unquote(__MODULE__)
      def normalize_access_token(response_body), do: {:ok, response_body}

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
