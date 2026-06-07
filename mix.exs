defmodule Assent.MixProject do
  use Mix.Project

  @source_url "https://github.com/pow-auth/assent"
  @version "0.3.1"

  def project do
    [
      app: :assent,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Hex
      description: "Multi-provider authentication framework",
      package: package(),

      # Docs
      name: "Assent",
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key, :inets]
    ]
  end

  defp deps do
    [
      # JWT libraries
      {:jose, "~> 1.8", optional: true},
      # HTTP clients
      {:certifi, ">= 0.0.0", optional: true},
      {:ssl_verify_fun, ">= 0.0.0", optional: true},
      {:req, "~> 0.4", optional: true},
      # Docs and tests
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:credo, "~> 1.1", only: [:dev, :test]},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:test_server, "~> 0.1.0", only: :test},
      {:plug, ">= 0.0.0", only: [:dev, :test]},
      {:bandit, ">= 0.0.0", only: :test}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      maintainers: ["Dan Schultzer"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Sponsor" => "https://github.com/sponsors/danschultzer"
      },
      files: ~w(CHANGELOG.md lib LICENSE mix.exs README.md)
    ]
  end

  defp docs do
    [
      source_ref: "v#{@version}",
      main: "Assent",
      canonical: "https://hexdocs.pm/assent",
      source_url: @source_url,
      extras: [
        "CHANGELOG.md": [filename: "CHANGELOG"]
      ],
      skip_undefined_reference_warnings_on: [
        "CHANGELOG.md"
      ],
      groups_for_modules: [
        "Base strategies": [Assent.Strategy.OAuth, Assent.Strategy.OAuth2, Assent.Strategy.OIDC],
        "Custom strategies": [
          Assent.Strategy,
          Assent.Strategy.OAuth.Base,
          Assent.Strategy.OAuth2.Base,
          Assent.Strategy.OIDC.Base
        ],
        Strategies: ~r/^Assent\.Strategy\./,
        HTTP: ~r/^Assent\.HTTPAdapter.*(?<!Error)$/,
        JWT: ~r/^Assent\.JWTAdapter.*(?<!Error)$/
      ]
    ]
  end
end
