defmodule Membrane.Pcap.Source.PipelineTest do
  use ExUnit.Case, async: false

  import Membrane.Testing.Assertions
  import Membrane.ChildrenSpec

  alias Membrane.Testing.{Pipeline, Sink}

  @tag time_consuming: true
  test "Pipeline does not crash when parsing small rtp stream" do
    expected_count = 6_227
    file = "test/support/fixtures/demo.pcap"
    process_file(file, expected_count)
  end

  #! Requires Git Large File Storage
  #! `brew install git-lfs`
  #! then clone this repo to download files
  @tag time_consuming: true
  test "Pipeline does not crash when parsing big RTP Stream" do
    expected_count = 47_942
    file = "test/support/fixtures/rtp_video_stream.pcap"
    process_file(file, expected_count)
  end

  defp process_file(file, expected_packets) do
    structure = [
      child(:source, %Membrane.Pcap.Source{path: file})
      |> child(:sink, Sink)
    ]

    {:ok, _supervisor_pid, pid} = Pipeline.start_link(structure: structure)

    Enum.each(1..expected_packets, fn _el ->
      assert_sink_buffer(pid, :sink, %Membrane.Buffer{})
    end)

    Membrane.Pipeline.terminate(pid)
  end
end
