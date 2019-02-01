defmodule Membrane.Element.Pcap.Source do
  use Membrane.Element.Base.Source

  alias Membrane.Buffer
  alias Membrane.Event.EndOfStream

  def_output_pads output: [
                    caps: :any
                  ]

  def_options packet_transformer: [
                type: :function,
                spec: (any() -> Buffer.t()),
                default: &__MODULE__.identity/1,
                description: """
                This function must transform parsed packet into a Buffer.
                """
              ],
              file: [
                type: :string,
                description: "Path to the .pcap file"
              ]

  defmodule State do
    @enforce_keys [:data, :transformer]
    defstruct @enforce_keys
  end

  @impl true
  def handle_init(%__MODULE__{file: file_path, packet_transformer: transformer}) do
    data = ExPcap.from_file(file_path).packets
    {:ok, %State{data: data, transformer: transformer}}
  end

  @impl true
  def handle_demand(pad, size, unit, context, state)

  def handle_demand(:output, _size, :buffers, _ctx, %State{data: []} = state) do
    {{:ok, [{:event, {:output, %EndOfStream{}}}]}, state}
  end

  def handle_demand(:output, size, :buffers, _ctx, state) do
    %State{data: data, transformer: transformer} = state
    {out, rest} = Enum.split(data, size)
    buffers = Enum.map(out, fn packet -> transformer.(packet) end)
    action = [buffer: {:output, buffers}]
    {{:ok, action}, %State{state | data: rest}}
  end

  # TODO change me in case of rewrite to streaming
  @spec identity(any()) :: any()
  def identity(%ExPcap.Packet{parsed_packet_data: {_, payload}}),
    do: %Buffer{payload: payload}
end
