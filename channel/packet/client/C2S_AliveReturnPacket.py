import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import C2S_ALIVE_RESPONSE


class AliveReturnPacket(Packet.Packet):
    def __init__(self):
        super().__init__(Packet.PacketType.C2S_ALIVE_RESPONSE, True)

    def build(self) -> Bin:
        packet_bin = Bin(C2S_ALIVE_RESPONSE)

        return packet_bin
