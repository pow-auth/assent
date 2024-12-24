Application.put_env(:assent, :http_adapter, Assent.HTTPAdapter.Httpc)

Logger.configure(level: :warning)

# For OTP 24 / Elixir 1.13 test
{:ok, _} = Application.ensure_all_started(:req)

ExUnit.start()
