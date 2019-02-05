defmodule Membrane.Element.Pcap.Parser do
  @moduledoc """
  This module is responsible for parsing `.pcap` files.
  """
  @enforce_keys [:file, :global_header]
  defstruct @enforce_keys
  use Bunch

  alias ExPcap.{Packet, PacketData, PacketHeader, MagicNumber, GlobalHeader}

  @type t :: %__MODULE__{
          file: IO.device(),
          global_header: ExPcap.GlobalHeader.t()
        }

  @doc """
  Opens a `pcap` file and parses global header.
  """
  @spec from_file(binary()) :: {:ok, __MODULE__.t()} | {:error, atom()}
  def from_file(path) do
    with {:ok, file} <- File.open(path, [:read, :binary]),
         %MagicNumber{} = magic_number <- MagicNumber.from_file(file),
         %GlobalHeader{} = global_header <- GlobalHeader.from_file(file, magic_number) do
      %__MODULE__{
        global_header: global_header,
        file: file
      }
      ~> {:ok, &1}
    else
      {:error, _} = error -> error
    end
  end

  @doc """
  Reads and parses a single packet from `.pcap` file.
  Each packet can't be read only once. After successful read
  cursor is moved to next packet.

  Uses `pkt` parser for processing packets. See [github](https://github.com/msantos/pkt) repo for details.
  """
  @spec next_packet(t()) :: {:ok, ExPcap.Packet.t() | :eof} | {:error, [any()], {atom(), any()}}
  def next_packet(%__MODULE__{file: file, global_header: global_header}) do
    with %PacketHeader{} = packet_header <- PacketHeader.from_file(file, global_header),
         %PacketData{} = packet_data <- PacketData.from_file(file, global_header, packet_header),
         {:ok, parsed_data} <- :pkt.decode(:ether, packet_data.data) do
      %Packet{
        packet_header: packet_header,
        raw_packet_data: packet_data,
        parsed_packet_data: parsed_data
      }
      ~> {:ok, &1}
    else
      :eof ->
        {:ok, :eof}

      {:error, _, _} = error ->
        error
    end
  end

  @doc """
  Closes `.pcap` file.
  """
  @spec destroy(Membrane.Element.Pcap.Parser.t()) :: :ok | {:error, atom()}
  def destroy(%__MODULE__{file: file}) do
    File.close(file)
  end
end
