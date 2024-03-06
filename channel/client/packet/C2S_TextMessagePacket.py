import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_TEXT_MESSAGE


class TextMessagePacket(Packet.Packet):
    def __init__(self, paramMessage: str):
        """
        Encrypted Message to the server (-> other clients)
        :param paramMessage: The message to be sent
        """
        super().__init__(Packet.PacketType.C2S_TEXT_MESSAGE, True)

        self.__message: str = paramMessage  # Message to be sent

    def getMessage(self) -> str:
        """
        Message being sent un-encoded
        :return: Message (str)
        """
        return self.__message

    def build(self) -> Bin:
        packet_bin = Bin(C2S_TEXT_MESSAGE)
        packet_bin.setAttribute("MESSAGE", self.getMessage().encode('utf-8'))  # Message to be sent encoded with utf-8

        return packet_bin
