defmodule Assent.TestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  using do
    quote do
      # We add this module attribute for backwards compatibility. Once Elixir 1.18 is
      # required we can default to JSON.
      @json_library (Code.ensure_loaded?(JSON) && JSON) || Jason
    end
  end
end
