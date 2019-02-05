defmodule Membrane.Support.TestPacket do
  @spec path() :: binary()
  def path, do: Path.join(["test", "support", "fixtures", "one_packet.pcap"])

  @spec expected_packet() :: ExPcap.Packet.t()
  def expected_packet,
    do: %ExPcap.Packet{
      packet_header: %ExPcap.PacketHeader{
        incl_len: 56,
        orig_len: 56,
        ts_sec: 1_549_020_145,
        ts_usec: 231_162
      },
      parsed_packet_data:
        {[
           {:ether, <<20, 171, 197, 198, 169, 248>>, <<136, 233, 254, 134, 210, 232>>, 2048, 0},
           {:ipv4, 4, 5, 0, 42, 33_633, 0, 0, 0, 64, 17, 53_033, {192, 168, 83, 168},
            {192, 168, 83, 63}, ""},
           {:udp, 58_888, 5_000, 22, 13_436}
         ], <<128, 96, 53, 16, 88, 254, 113, 175, 47, 32, 241, 45, 9, 16>>},
      raw_packet_data: %ExPcap.PacketData{
        data:
          <<20, 171, 197, 198, 169, 248, 136, 233, 254, 134, 210, 232, 8, 0, 69, 0, 0, 42, 131,
            97, 0, 0, 64, 17, 207, 41, 192, 168, 83, 168, 192, 168, 83, 63, 230, 8, 19, 136, 0,
            22, 52, 124, 128, 96, 53, 16, 88, 254, 113, 175, 47, 32, 241, 45, 9, 16>>,
        data_len: 56
      }
    }

  @spec expected_header() :: ExPcap.GlobalHeader.t()
  def expected_header,
    do: %ExPcap.GlobalHeader{
      magic_number: %ExPcap.MagicNumber{
        magic: 3_569_595_041,
        nanos: false,
        reverse_bytes: true
      },
      network: 1,
      sigfigs: 0,
      snaplen: 262_144,
      thiszone: 0,
      version_major: 2,
      version_minor: 4
    }
end
