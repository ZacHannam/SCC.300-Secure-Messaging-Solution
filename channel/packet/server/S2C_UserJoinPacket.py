import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import C2S_USER_DATA


class UserJoinPacket(Packet.Packet):
    def __init__(self, paramDisplayName: str):
        super().__init__(Packet.PacketType.S2C_USER_JOIN, True)

        self.__displayName = paramDisplayName

    def getDisplayName(self) -> str:
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(C2S_USER_DATA)

        packet_bin.setAttribute("DISPLAY_NAME", self.getDisplayName().encode())

        return packet_bin
