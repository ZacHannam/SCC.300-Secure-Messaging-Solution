import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_ALIVE


class AlivePacket(Packet.Packet):
    def __init__(self):
        """
        Sent to the client to check if they are alive
        """
        super().__init__(Packet.PacketType.S2C_ALIVE, True)

    def build(self) -> Bin:
        packet_bin = Bin(S2C_ALIVE)

        # No information is needed other than the packet type which is added in the headers
        return packet_bin
