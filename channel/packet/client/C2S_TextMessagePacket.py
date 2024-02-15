import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import C2S_TEXT_MESSAGE


class TextMessagePacket(Packet.Packet):
    def __init__(self, paramMessage: str):
        super().__init__(Packet.PacketType.C2S_TEXT_MESSAGE, True)

        self.__message = paramMessage

    def getMessage(self) -> str:
        return self.__message

    def build(self) -> Bin:
        packet_bin = Bin(C2S_TEXT_MESSAGE)
        packet_bin.setAttribute("MESSAGE", self.getMessage().encode('utf-8'))

        return packet_bin
