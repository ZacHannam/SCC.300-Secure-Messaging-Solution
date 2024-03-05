import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import S2C_TEXT_MESSAGE


class TextMessagePacket(Packet.Packet):
    def __init__(self, paramDisplayName: str, paramMessage: str):
        super().__init__(Packet.PacketType.S2C_TEXT_MESSAGE, True)

        self.__displayName = paramDisplayName
        self.__message = paramMessage

    def getMessage(self) -> str:
        return self.__message

    def getDisplayName(self) -> str:
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(S2C_TEXT_MESSAGE)

        packet_bin.setAttribute( "DISPLAY_NAME" , self.getDisplayName().encode() )
        packet_bin.setAttribute( "MESSAGE"      , self.getMessage().encode('utf-8')  )

        return packet_bin
