defmodule Membrane.Element.Pcap.Source.PipelineTest do
  use ExUnit.Case, async: false

  alias Membrane.Testing
  import Membrane.Testing.Pipeline.Assertions

  @tag time_consuming: true
  test "Pipeline does not crash when parsing small rtp stream" do
    expected_count = 6_227
    file = "test/support/fixtures/demo.pcap"
    process_file(file, expected_count)
  end

  @tag time_consuming: true
  test "Pipeline does not crash when parsing big RTP Stream" do
    expected_count = 47_942
    file = "test/support/fixtures/rtp_video_stream.pcap"
    process_file(file, expected_count)
  end

  defp process_file(file, expected_packets) do
    options = %Testing.Pipeline.Options{
      elements: [
        source: %Membrane.Element.Pcap.Source{path: file},
        sink: %Membrane.Testing.Sink{target: self()}
      ],
      monitored_callbacks: [:handle_prepared_to_playing],
      test_process: self()
    }

    {:ok, pid} = Testing.Pipeline.start_link(options)

    Membrane.Pipeline.play(pid)
    assert_receive_message(:handle_prepared_to_playing, 1000)

    Enum.each(1..expected_packets, fn _el ->
      assert_receive %Membrane.Buffer{} = buffer, 1000
    end)
  end
end
