import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import C2S_USER_DATA
from utils.codecs.Base64 import base64ToInt


class UserDataPacket(Packet.Packet):
    def __init__(self, paramDisplayName: str):
        super().__init__(Packet.PacketType.C2S_USER_DATA, True)

        self.__displayName = paramDisplayName

    def getDisplayName(self) -> str:
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(C2S_USER_DATA)

        packet_bin.setAttribute("DISPLAY_NAME_LENGTH", len(self.getDisplayName()))
        packet_bin.setAttribute("DISPLAY_NAME", base64ToInt(self.getDisplayName()))

        return packet_bin
