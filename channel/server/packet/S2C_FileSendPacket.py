import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_FILE_SEND


class FileSendPacket(Packet.Packet):
    def __init__(self, paramFileName: str, paramFileData: bytes, paramFileSender: str):
        """
        Encrypted packet containing the file information
        :param paramFileName:
        """
        super().__init__(Packet.PacketType.S2C_FILE_SEND, True)

        self.__fileName: str = paramFileName  # File name
        self.__fileData: bytes = paramFileData  # File bytes
        self.__fileSender: str = paramFileSender  # File sender

    def getFileName(self) -> str:
        """
        The files name
        :return: file name
        """
        return self.__fileName

    def getFileData(self) -> bytes:
        """
        Get the file data
        :return: File data (bytes)
        """
        return self.__fileData

    def getFileSender(self) -> str:
        """
        Get the person who sent the file
        :return: Person who sent the file
        """
        return self.__fileSender

    def build(self) -> Bin:
        packet_bin = Bin(S2C_FILE_SEND)

        # The file name encoded in utf-8
        packet_bin.setAttribute("FILE_SENDER", self.getFileSender().encode('utf-8'))
        packet_bin.setAttribute("FILE_NAME", self.getFileName().encode('utf-8'))
        packet_bin.setAttribute("FILE_DATA", self.getFileData())  # Set the file data

        return packet_bin
