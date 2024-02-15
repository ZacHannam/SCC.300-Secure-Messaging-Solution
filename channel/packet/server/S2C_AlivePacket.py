import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import S2C_ALIVE


class AlivePacket(Packet.Packet):
    def __init__(self):
        super().__init__(Packet.PacketType.S2C_ALIVE, True)

    def build(self) -> Bin:
        packet_bin = Bin(S2C_ALIVE)

        return packet_bin
