import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_FILE_SEND


class FileSendPacket(Packet.Packet):
    def __init__(self, paramFileName: str, paramFileData: bytes):
        """
        Encrypted packet containing the file information
        :param paramFileName:
        """
        super().__init__(Packet.PacketType.C2S_FILE_SEND, True)

        self.__fileName: str = paramFileName  # File name
        self.__fileData: bytes = paramFileData  # File bytes

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

    def build(self) -> Bin:
        packet_bin = Bin(C2S_FILE_SEND)

        # The file name encoded in utf-8
        packet_bin.setAttribute("FILE_NAME", self.getFileName().encode('utf-8'))
        packet_bin.setAttribute("FILE_DATA", self.getFileData())  # Set the file data

        return packet_bin
