import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import C2S_USER_LEAVE


class UserLeavePacket(Packet.Packet):
    def __init__(self):
        super().__init__(Packet.PacketType.C2S_USER_LEAVE, True)

    def build(self) -> Bin:
        packet_bin = Bin(C2S_USER_LEAVE)

        return packet_bin
