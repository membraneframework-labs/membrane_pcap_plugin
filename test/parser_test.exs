defmodule Membrane.Element.Pcap.ParserTest do
  use ExUnit.Case, async: false

  alias Membrane.Element.Pcap.Parser
  alias Membrane.Support.TestPacket

  test "parses example file" do
    assert {:ok, parser} = Parser.from_file(TestPacket.path())
    assert %Parser{file: file, global_header: global_header} = parser
    assert is_pid(file)
    assert global_header == TestPacket.expected_header()
    assert {:ok, TestPacket.expected_packet()} == Parser.next_packet(parser)
    assert Parser.next_packet(parser) == {:ok, :eof}
    assert Parser.destroy(parser) == :ok
  end
end
