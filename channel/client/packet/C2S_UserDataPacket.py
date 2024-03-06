import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_USER_DATA


class UserDataPacket(Packet.Packet):
    def __init__(self, paramDisplayName: str):
        """
        Encrypted packet containing the user's information
        :param paramDisplayName:
        """
        super().__init__(Packet.PacketType.C2S_USER_DATA, True)

        self.__displayName: str = paramDisplayName  # User's display name

    def getDisplayName(self) -> str:
        """
        The client's chosen display name
        :return:
        """
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(C2S_USER_DATA)

        # The chosen display name encoded using utf-8
        packet_bin.setAttribute("DISPLAY_NAME", self.getDisplayName().encode('utf-8'))

        return packet_bin
