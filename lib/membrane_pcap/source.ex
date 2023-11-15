defmodule Membrane.Pcap.Source do
  @moduledoc """
  Element that reads subsequent packets from `pcap` file and sends them
  as buffers through the output pad.
  """
  use Membrane.Source
  use Bunch

  alias Membrane.Buffer
  alias Membrane.Pcap.Parser
  alias Membrane.RemoteStream
  alias Membrane.ResourceGuard
  alias ExPcap.Packet

  @next_packet &Parser.next_packet/1

  def_output_pad :output,
    accepted_format: %RemoteStream{type: :packetized, content_format: nil},
    flow_control: :manual

  def_options packet_transformer: [
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
  def handle_init(_ctx, %__MODULE__{path: path, packet_transformer: transformer}) do
    {[],
     %State{
       path: path,
       transformer: transformer
     }}
  end

  @impl true
  def handle_setup(ctx, %State{path: path} = state) do
    case Parser.from_file(path) do
      {:ok, parser} ->
        ResourceGuard.register(
          ctx.resource_guard,
          fn -> Parser.destroy(parser) end,
          tag: {:path, path}
        )

        {[], %State{state | parser: parser}}

      {:error, reason} ->
        raise "Calling Membrane.Pcap.Parser.from_file(#{inspect(path)}) returned an error with reason: #{inspect(reason)}"
    end
  end

  @impl true
  def handle_playing(_ctx, state) do
    actions = [stream_format: {:output, %RemoteStream{type: :packetized}}]
    {actions, state}
  end

  @impl true
  def handle_demand(:output, size, :buffers, _ctx, state) do
    %State{parser: parser, transformer: transformer} = state

    case fetch_packets(size, parser, transformer) do
      {:error, reason} ->
        raise "Fetching packets failed with error reason: #{inspect(reason)}"

      result ->
        {pack_fetched_packets(result), state}
    end
  end

  @spec default_transformer(Packet.t()) :: Buffer.t()
  def default_transformer(%Packet{parsed_packet_data: {_, payload}}) do
    %Buffer{payload: payload}
  end

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
    do: [buffer: {:output, Enum.reverse(buffers)}]
end
