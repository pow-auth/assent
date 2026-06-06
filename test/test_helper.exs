Application.put_env(:assent, :http_adapter, Assent.HTTPAdapter.Httpc)

Logger.configure(level: :warning)

ExUnit.start()
