defmodule IntegrationServer.MixProject do
  use Mix.Project

  def project do
    [
      app: :integration_server,
      version: "0.0.1",
      elixir: "~> 1.13",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {IntegrationServer.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:assent, path: "../"},
      {:plug, ">= 0.0.0"},
      {:bandit, ">= 0.0.0"},
      {:dialyxir, "~> 1.4", runtime: false},
      {:req, ">= 0.0.0"}
    ]
  end
end
