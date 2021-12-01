defmodule Membrane.Element.Pcap.MixProject do
  use Mix.Project

  @version "0.4.0"
  @github_url "https://github.com/membraneframework/membrane-element-pcap"

  def project do
    [
      app: :membrane_element_pcap,
      version: @version,
      elixir: "~> 1.12",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      description: "Membrane Multimedia Framework (Pcap Element)",
      package: package(),
      name: "Membrane Element: Pcap",
      source_url: @github_url,
      docs: docs(),
      homepage_url: "https://membraneframework.org",
      deps: deps(),
      aliases: aliases(),
      preferred_cli_env: [
        "test.short": :test
      ],
      dialyzer: [
        plt_add_apps: [:pkt]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:pkt]
    ]
  end

  def aliases do
    [
      "test.short": "test --exclude time_consuming:true"
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end

  defp package do
    [
      maintainers: ["Membrane Team"],
      licenses: ["Apache 2.0"],
      links: %{
        "GitHub" => @github_url,
        "Membrane Framework Homepage" => "https://membraneframework.org"
      }
    ]
  end

  defp deps do
    [
      {:membrane_core, "~> 0.8.0"},
      {:ex_doc, "~> 0.26", only: :dev, runtime: false},
      {:dialyxir, "~> 1.1.0", only: [:dev], runtime: false},
      {:ex_pcap, github: "membraneframework/expcap"},
      {:mock, "~> 0.3.0", only: :test}
    ]
  end
end
