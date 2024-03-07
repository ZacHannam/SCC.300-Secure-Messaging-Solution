import channel.Packet as Packet
from Properties import RECEIVE_FILES
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_USER_DATA


class UserDataPacket(Packet.Packet):
    def __init__(self, paramDisplayName: str, paramServerSecret: str | None):
        """
        Encrypted packet containing the user's information
        :param paramDisplayName:
        """
        super().__init__(Packet.PacketType.C2S_USER_DATA, True)

        self.__displayName: str = paramDisplayName  # User's display name
        self.__serverSecret: str | None = paramServerSecret

    def getDisplayName(self) -> str:
        """
        The client's chosen display name
        :return:
        """
        return self.__displayName

    def getServerSecret(self) -> str | None:
        """
        Return the server secret if it is set
        :return:
        """
        return self.__serverSecret

    def build(self) -> Bin:
        packet_bin = Bin(C2S_USER_DATA)

        # The chosen display name encoded using utf-8
        packet_bin.setAttribute("DISPLAY_NAME", self.getDisplayName().encode('utf-8'))
        packet_bin.setAttribute("RECEIVE_FILES", int(RECEIVE_FILES))

        if self.getServerSecret() is not None:
            packet_bin.setAttribute("SERVER_SECRET", self.getServerSecret().encode('utf-8'))

        return packet_bin
