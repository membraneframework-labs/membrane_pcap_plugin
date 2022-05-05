defmodule Membrane.Pcap.SourceTest do
  use ExUnit.Case
  use Bunch
  import Mock

  alias Membrane.Pcap.{Source, Parser}
  alias Source.State

  setup do
    [state: %State{path: "some_location.pcap", transformer: &Source.default_transformer/1}]
  end

  describe "Pcap Source element when handling prepared to playing should" do
    test "update state with open parser on success", %{state: state} do
      with_mock Parser, from_file: fn _ -> {:ok, :parser} end do
        caps = [caps: {:output, %Membrane.RemoteStream{type: :packetized}}]

        assert {{:ok, caps}, %State{state | parser: :parser}} ==
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

  describe "Pcap Source element when handling demand should" do
    setup do
      base = 1..3

      packets =
        Enum.map(base, fn elem -> {:ok, %ExPcap.Packet{parsed_packet_data: {[], elem}}} end)

      {:ok, store} = Agent.start_link(fn -> packets ++ [{:ok, :eof}] end)

      next_packet = fn _ ->
        Agent.get_and_update(store, fn value ->
          Enum.split(value, 1)
          |> then(fn {[value], rest} -> {value, rest} end)
        end)
      end

      [base: base, packets: packets, next_packet: next_packet, store: store]
    end

    test "should return event end of stream when eof is sent as last action",
         %{state: state, next_packet: next_packet, base: base} do
      with_mock Parser, next_packet: next_packet do
        assert {{:ok, actions}, ^state} = Source.handle_demand(:output, 4, :buffers, nil, state)
        assert length(actions) == 2
        assert {:output, buffers} = Keyword.fetch!(actions, :buffer)

        buffers
        |> Enum.zip(base)
        |> Enum.each(fn {left, right} -> assert left.payload == right end)

        assert Keyword.fetch!(actions, :end_of_stream) == :output
      end
    end

    test "when all packets are ignored no buffers are sent",
         %{state: state, next_packet: next_packet} do
      ignore_all_transformer = fn _ -> nil end

      with_mock Parser, next_packet: next_packet do
        state = %Source.State{state | transformer: ignore_all_transformer}
        assert {{:ok, actions}, ^state} = Source.handle_demand(:output, 4, :buffers, nil, state)
        refute Keyword.has_key?(actions, :buffer)
        assert :output = Keyword.fetch!(actions, :end_of_stream)
      end
    end

    test "return buffers when they are not ignored", %{state: state, next_packet: next_packet} do
      ignore_even_buffers = fn
        %ExPcap.Packet{parsed_packet_data: {[], value}} ->
          if rem(value, 2) == 0 do
            %Membrane.Buffer{payload: value}
          else
            nil
          end
      end

      with_mock Parser, next_packet: next_packet do
        state = %Source.State{state | transformer: ignore_even_buffers}
        assert {{:ok, actions}, ^state} = Source.handle_demand(:output, 4, :buffers, nil, state)

        assert actions == [
                 buffer: {:output, [%Membrane.Buffer{metadata: %{}, payload: 2}]},
                 end_of_stream: :output
               ]
      end
    end
  end
end
