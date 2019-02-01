defmodule Membrane.Element.Pcap.Source.PipelineTest do
  use ExUnit.Case

  alias Membrane.Testing
  import Membrane.Testing.Pipeline.Assertions

  @expected_packets 6227

  test "Pipeline does not crash" do
    {:ok, pid} =
      Testing.Pipeline.start_link(%Testing.Pipeline.Options{
        elements: [
          source: %Membrane.Element.Pcap.Source{
            file: "test/support/fixtures/demo.pcap"
          },
          sink: %Membrane.Testing.Sink{target: self()}
        ],
        monitored_callbacks: [:handle_prepared_to_playing],
        test_process: self()
      })

    Membrane.Pipeline.play(pid)
    assert_receive_message(:handle_prepared_to_playing, 1000)

    Enum.each(1..@expected_packets, fn _ ->
      assert_receive %Membrane.Buffer{}, 1000
    end)
  end
end
