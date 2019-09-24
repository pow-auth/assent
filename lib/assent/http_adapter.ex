defmodule Assent.HTTPAdapter do
  @moduledoc false

  defmodule HTTPResponse do
    @moduledoc false

    @type header :: {binary(), binary()}
    @type t      :: %__MODULE__{
      status: integer(),
      headers: [header()],
      body: binary()
    }

    defstruct status: 200, headers: [], body: ""
  end

  @type method :: :get | :post
  @type body :: binary() | nil
  @type headers :: [{binary(), binary()}]

  @callback request(method(), binary(), body(), headers(), Keyword.t()) :: {:ok, map()} | {:error, any()}

  @spec user_agent_header() :: {binary(), binary()}
  def user_agent_header() do
    version = Application.spec(:assent, :vsn) || "0.0.0"

    {"User-Agent", "Assent-#{version}"}
  end
end
