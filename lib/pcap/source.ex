defmodule Membrane.Element.Pcap.Source do
  @moduledoc """
  Element that reads subsequent packets from `pcap` file and sends them
  as buffers through the output pad.
  """
  use Membrane.Source
  use Bunch

  alias Membrane.Buffer
  alias Membrane.Event.EndOfStream
  alias Membrane.Element.Pcap.Parser
  alias ExPcap.Packet

  @next_packet &Parser.next_packet/1

  def_output_pad :output,
    caps: :any

  def_options packet_transformer: [
                type: :function,
                spec: (Packet.t() -> Buffer.t() | nil),
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
  def handle_demand(:output, size, :buffers, _ctx, state) do
    %State{parser: parser, transformer: transformer} = state

    size
    |> fetch_packets(parser, transformer)
    ~> (
      {:error, _} = error ->
        {error, state}

      result ->
        result
        |> pack_fetched_packets()
        ~> {{:ok, &1}, state}
    )
  end

  @spec default_transformer(Packet.t()) :: Buffer.t()
  def default_transformer(%ExPcap.Packet{parsed_packet_data: {_, payload}}),
    do: %Buffer{payload: payload}

  # Note: Will return buffers in reversed order
  defp fetch_packets(count, parser, transformer, acc \\ [])
  defp fetch_packets(0, _, _, acc), do: acc

  defp fetch_packets(count, parser, transformer, acc) do
    case @next_packet.(parser) do
      {:error, _, _} ->
        {:error, :unparsable_data}

      {:ok, :eof} ->
        {:eof, acc}

      {:ok, %Packet{} = packet} ->
        case transformer.(packet) do
          nil ->
            fetch_packets(count, parser, transformer, acc)

          buffer ->
            fetch_packets(count - 1, parser, transformer, [buffer | acc])
        end
    end
  end

  defp pack_fetched_packets(result)

  defp pack_fetched_packets({:eof, []}), do: [end_of_stream: :output]

  defp pack_fetched_packets({:eof, buffers}),
    do: pack_fetched_packets(buffers) ++ pack_fetched_packets({:eof, []})

  defp pack_fetched_packets(buffers) when is_list(buffers),
    do: buffers |> Enum.reverse() ~> [buffer: {:output, &1}]
end
