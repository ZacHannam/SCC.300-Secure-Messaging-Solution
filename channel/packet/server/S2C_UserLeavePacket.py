import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import S2C_USER_LEAVE


class UserLeavePacket(Packet.Packet):
    def __init__(self, paramDisplayName: str):
        super().__init__(Packet.PacketType.S2C_USER_LEAVE, True)

        self.__displayName = paramDisplayName

    def getDisplayName(self) -> str:
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(S2C_USER_LEAVE)

        packet_bin.setAttribute("DISPLAY_NAME", self.getDisplayName().encode())

        return packet_bin
