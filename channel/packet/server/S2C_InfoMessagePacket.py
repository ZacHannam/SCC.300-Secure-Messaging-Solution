import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import S2C_INFO_MESSAGE


class InfoMessagePacket(Packet.Packet):
    def __init__(self, paramMessage: str):
        super().__init__(Packet.PacketType.S2C_INFO_MESSAGE, True)

        self.__message = paramMessage

    def getMessage(self) -> str:
        return self.__message

    def build(self) -> Bin:
        packet_bin = Bin(S2C_INFO_MESSAGE)
        packet_bin.setAttribute("MESSAGE", self.getMessage().encode('utf-8'))

        return packet_bin
