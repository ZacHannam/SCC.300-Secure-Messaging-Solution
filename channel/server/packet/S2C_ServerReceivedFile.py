import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_SERVER_RECEIVED_FILE


class ServerReceivedFile(Packet.Packet):
    def __init__(self, paramFileName: str):
        """
        Encrypted packet to tell client it received file
        :param paramFileName:
        """
        super().__init__(Packet.PacketType.S2C_SERVER_RECEIVED_FILE, True)

        self.__fileName: str = paramFileName  # File name
        self.__error: str | None = None

    def getFileName(self) -> str:
        """
        The files name
        :return: file name
        """
        return self.__fileName

    def getError(self) -> str | None:
        """
        The files name
        :return: file name
        """
        return self.__error

    def setError(self, paramError: str) -> None:
        """
        Set the error field
        :param paramError: Error that occurred
        :return: None
        """
        self.__error = paramError

    def build(self) -> Bin:
        packet_bin = Bin(S2C_SERVER_RECEIVED_FILE)

        # The file name encoded in utf-8
        packet_bin.setAttribute("FILE_NAME", self.getFileName().encode('utf-8'))

        if self.getError() is not None:
            packet_bin.setAttribute("ERROR", self.getError().encode('utf-8'))

        return packet_bin
