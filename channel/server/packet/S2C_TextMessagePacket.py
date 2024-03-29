import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_TEXT_MESSAGE


class TextMessagePacket(Packet.Packet):
    def __init__(self, paramDisplayName: str, paramMessage: str):
        """
        Sent to the client when someone sends a message
        :param paramDisplayName:
        :param paramMessage:
        """
        super().__init__(Packet.PacketType.S2C_TEXT_MESSAGE, True)

        self.__displayName: str = paramDisplayName  # Display name of sender
        self.__message: str = paramMessage  # Message sent

    def getMessage(self) -> str:
        """
        Get the message being sent
        :return: Message (str)
        """
        return self.__message

    def getDisplayName(self) -> str:
        """
        Get the sender's display name
        :return: Display name of sender (str)
        """
        return self.__displayName

    def build(self) -> Bin:
        packet_bin = Bin(S2C_TEXT_MESSAGE)

        # Set the display name of sender encoded with utf-8
        packet_bin.setAttribute( "DISPLAY_NAME" , self.getDisplayName().encode('utf-8') )

        # Set the message being sent encoded with utf-8
        packet_bin.setAttribute( "MESSAGE"      , self.getMessage().encode('utf-8')  )

        return packet_bin
