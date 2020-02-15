defmodule Assent.MixProject do
  use Mix.Project

  @version "0.1.8"

  def project do
    [
      app: :assent,
      version: @version,
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Hex
      description: "Multi-provider framework",
      package: package(),

      # Docs
      name: "Assent",
      docs: docs(),

      xref: [exclude: [JOSE.JWT, JOSE.JWK, JOSE.JWS, Mint.HTTP, :certifi, :ssl_verify_hostname]]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :ssl, :inets]
    ]
  end

  defp deps do
    [
      {:oauther, "~> 1.1"},

      {:jose, "~> 1.8", optional: true},

      {:certifi, ">= 0.0.0", optional: true},
      {:ssl_verify_fun, ">= 0.0.0", optional: true},

      {:mint, ">= 0.1.0 and < 1.1.0", optional: true},
      {:castore, "~> 0.1.0", optional: true},

      {:credo, "~> 1.1.0", only: [:dev, :test]},
      {:jason, "~> 1.0", only: [:dev, :test]},

      {:ex_doc, "~> 0.21.0", only: :dev},

      {:bypass, "~> 1.0.0", only: :test}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      maintainers: ["Dan Shultzer"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/pow-auth/assent"},
      files: ~w(lib LICENSE mix.exs README.md)
    ]
  end

  defp docs do
    [
      source_ref: "v#{@version}",
      main: "README",
      canonical: "http://hexdocs.pm/assent",
      source_url: "https://github.com/pow-auth/assent",
      extras: [
        "README.md": [filename: "README"],
        "CHANGELOG.md": [filename: "CHANGELOG"],
      ],
      groups_for_modules: [
        Strategies: ~r/^Assent.Strategy/
      ]
    ]
  end
end
