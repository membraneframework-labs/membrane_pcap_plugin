defmodule Membrane.Element.Pcap.Source do
  @moduledoc """
  Element that reads subsequent packets from `pcap` file and sends them
  as buffers through the output pad.
  """
  use Membrane.Element.Base.Source
  use Bunch

  alias Membrane.Buffer
  alias Membrane.Event.EndOfStream
  alias Membrane.Element.Pcap.Parser
  alias ExPcap.Packet

  @next_packet &Parser.next_packet/1

  def_output_pads output: [
                    caps: :any
                  ]

  def_options packet_transformer: [
                type: :function,
                spec: (Packet.t() -> Buffer.t()),
                default: &__MODULE__.default_transformer/1,
                description: """
                This function transforms parsed packet into a buffer.
                It is applied on each packet.

                It allows enriching buffers with metadata extracted from
                packets f.e. packet source address or port.
                """
              ],
              path: [
                type: :string,
                description: "Path to the .pcap file"
              ]

  defmodule State do
    @moduledoc false
    @enforce_keys [:transformer, :path]
    defstruct @enforce_keys ++ [:parser]

    @type t :: %__MODULE__{
            transformer: (Packet.t() -> Buffer.t()),
            path: binary()
          }
  end

  @impl true
  def handle_init(%__MODULE__{path: path, packet_transformer: transformer}) do
    %State{
      path: path,
      transformer: transformer
    }
    ~> {:ok, &1}
  end

  @impl true
  def handle_prepared_to_playing(_context, %State{path: path} = state) do
    case Parser.from_file(path) do
      {:ok, parser} -> {:ok, %State{state | parser: parser}}
      {:error, _} = error -> {error, state}
    end
  end

  @impl true
  def handle_prepared_to_stopped(_context, %State{parser: parser} = state) do
    Parser.destroy(parser)
    {:ok, %State{state | parser: nil}}
  end

  @impl true
  def handle_demand(:output, size, :buffers, _ctx, %State{parser: parser} = state) do
    size
    |> fetch_next_packets(parser)
    |> handle_fetched_packets(state)
  end

  @spec default_transformer(any()) :: any()
  def default_transformer(%ExPcap.Packet{parsed_packet_data: {_, payload}}),
    do: %Buffer{payload: payload}

  # Note: Will return buffers in reversed order
  defp fetch_next_packets(count, parser) do
    Enum.reduce_while(1..count, [], fn _, acc ->
      case @next_packet.(parser) do
        {:error, _, _} = error -> {:halt, error}
        {:ok, :eof} -> {:halt, [:eof | acc]}
        {:ok, %Packet{} = packet} -> {:cont, [packet | acc]}
      end
    end)
  end

  defp handle_fetched_packets(result, state)

  defp handle_fetched_packets({:error, _, _} = error, state), do: {error, state}

  # Note: assumes packets are in reversed order
  defp handle_fetched_packets(buffers, %State{transformer: transformer} = state) do
    buffers
    |> pack_packets(transformer)
    |> Enum.reverse()
    ~> {{:ok, &1}, state}
  end

  defp pack_packets(buffers, transformer) do
    Enum.reduce(buffers, [buffer: {:output, []}], fn
      :eof, acc ->
        [{:event, {:output, %EndOfStream{}}} | acc]

      %Packet{} = packet, acc ->
        Keyword.update(acc, :buffer, [], fn {:output, buffers} ->
          transformer.(packet)
          ~> {:output, [&1 | buffers]}
        end)
    end)
  end
end
