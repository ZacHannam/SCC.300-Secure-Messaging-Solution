import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_INFO_MESSAGE


class InfoMessagePacket(Packet.Packet):
    def __init__(self, paramMessage: str):
        """
        Raw message to appear on client's terminal
        :param paramMessage: Message to be displayed
        """
        super().__init__(Packet.PacketType.S2C_INFO_MESSAGE, True)

        self.__message = paramMessage  # Set the message

    def getMessage(self) -> str:
        """
        Raw message to be display on client
        :return: Message (str)
        """
        return self.__message

    def build(self) -> Bin:
        packet_bin = Bin(S2C_INFO_MESSAGE)

        # Set the raw message encoded in utf-8
        packet_bin.setAttribute("MESSAGE", self.getMessage().encode('utf-8'))

        return packet_bin
