defmodule Membrane.Element.Pcap.SourceTest do
  use ExUnit.Case
  use Bunch
  import Mock

  alias Membrane.Element.Pcap.{Source, Parser}
  alias Source.State

  setup do
    [state: %State{path: "some_location.pcap", transformer: &Source.default_transformer/1}]
  end

  describe "Pcap Source element when handling prepared to playing should" do
    test "update state with open parser on success", %{state: state} do
      with_mock Parser, from_file: fn _ -> {:ok, :parser} end do
        assert {:ok, %State{state | parser: :parser}} ==
                 Source.handle_prepared_to_playing(nil, state)

        assert_called(Parser.from_file(state.path))
      end
    end

    test "return an error if it fails to open file", %{state: state} do
      assert {{:error, :enoent}, ^state} = Source.handle_prepared_to_playing(nil, state)
    end
  end

  test "Pcap Source element when handling prepared to stopped should destroy open parser", %{
    state: state
  } do
    with_mock Parser, destroy: fn _ -> :ok end do
      Source.handle_prepared_to_stopped(nil, %State{state | parser: :parser})
      assert_called(Parser.destroy(:parser))
    end
  end

  test "Pcap Source element when parsing packet should return event end of stream when eof is sent as last action",
       %{state: state} do
    packets = Enum.map(1..3, fn elem -> {:ok, %ExPcap.Packet{parsed_packet_data: {[], elem}}} end)
    {:ok, store} = Agent.start_link(fn -> packets ++ [{:ok, :eof}] end)

    next_packet = fn _ ->
      Agent.get_and_update(store, fn value ->
        Enum.split(value, 1)
        ~> ({[value], rest} -> {value, rest})
      end)
    end

    with_mock Parser, next_packet: next_packet do
      assert {{:ok, actions}, ^state} = Source.handle_demand(:output, 4, :buffers, nil, state)
      assert length(actions) == 2
      assert {:output, buffers} = Keyword.fetch!(actions, :buffer)

      buffers
      |> Enum.zip(1..3)
      |> Enum.each(fn {left, right} -> assert left.payload == right end)

      assert Keyword.fetch!(actions, :event) == {:output, %Membrane.Event.EndOfStream{}}
    end
  end
end
