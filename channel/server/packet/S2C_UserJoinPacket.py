import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_USER_JOIN


class UserJoinPacket(Packet.Packet):
    def __init__(self, paramDisplayName: str):
        """
        Sent to client when a user joins
        :param paramDisplayName:
        """
        super().__init__(Packet.PacketType.S2C_USER_JOIN, True)

        self.__displayName: str = paramDisplayName  # Username of the person that has joined

    def getDisplayName(self) -> str:
        """
        Display name of the user that has joined
        :return: Display Name (str)
        """
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(S2C_USER_JOIN)

        # Set the display name of the user that has left encoded with utf-8
        packet_bin.setAttribute("DISPLAY_NAME", self.getDisplayName().encode())

        return packet_bin
