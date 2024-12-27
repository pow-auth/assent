defmodule IntegrationServer.Application do
  use Application

  def start(_type, _args) do
    children = [
      {Bandit, plug: IntegrationServer.Router}
    ]

    opts = [strategy: :one_for_one, name: IntegrationServer.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
