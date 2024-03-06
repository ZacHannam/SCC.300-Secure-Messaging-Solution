import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_USER_LEAVE


class UserLeavePacket(Packet.Packet):
    def __init__(self, paramDisplayName: str):
        """
        The packet sent to the client when another user leaves
        :param paramDisplayName:
        """
        super().__init__(Packet.PacketType.S2C_USER_LEAVE, True)

        self.__displayName: str = paramDisplayName  # The display name of the user that leaves

    def getDisplayName(self) -> str:
        """
        Display name of the user that has left
        :return: Display Name (str)
        """
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(S2C_USER_LEAVE)

        # Set the display name of the user that has left encoded with utf-8
        packet_bin.setAttribute("DISPLAY_NAME", self.getDisplayName().encode('utf-8'))

        return packet_bin
