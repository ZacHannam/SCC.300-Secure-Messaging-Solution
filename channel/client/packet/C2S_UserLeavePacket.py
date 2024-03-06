import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_USER_LEAVE


class UserLeavePacket(Packet.Packet):
    def __init__(self):
        """
        Encrypted packet sent to server when the user leaves the server
        """
        super().__init__(Packet.PacketType.C2S_USER_LEAVE, True)

    def build(self) -> Bin:
        packet_bin = Bin(C2S_USER_LEAVE)

        # No information is needed other than the packet type which is added in the headers
        return packet_bin
