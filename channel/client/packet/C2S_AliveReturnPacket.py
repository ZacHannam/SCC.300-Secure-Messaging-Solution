import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_ALIVE_RESPONSE


class AliveReturnPacket(Packet.Packet):
    """
    Return packet sent from client to server to indicate that it is still alive
    """
    def __init__(self):
        super().__init__(Packet.PacketType.C2S_ALIVE_RESPONSE, True)

    def build(self) -> Bin:
        packet_bin = Bin(C2S_ALIVE_RESPONSE)

        # No information is needed other than the packet type which is added in the headers
        return packet_bin
