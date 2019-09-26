defmodule Assent.JWTAdapter.JOSE do
  @moduledoc """
  JWT adapter module for parsing JWT tokens with JOSE.
  """
  alias Assent.{JWTAdapter, JWTAdapter.JWT}

  @behaviour Assent.JWTAdapter

  @impl JWTAdapter
  def decode(token, json_library: json_library) do
    JOSE.json_module(json_library)

    {:ok, %JWT{
      payload: JOSE.JWT.peek_payload(token).fields
    }}
  end
end
