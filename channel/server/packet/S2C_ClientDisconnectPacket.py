import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_CLIENT_DISCONNECT


class ClientDisconnectPacket(Packet.Packet):
    def __init__(self, paramReason: str | None):
        """
        Sent to the client to disconnect them
        :param paramReason: The reason they are being disconnected
        """
        super().__init__(Packet.PacketType.S2C_CLIENT_DISCONNECT, True)

        self.__reason = paramReason  # The reason the client is being disconnected

    def getReason(self) -> str | None:
        """
        Get the reason the client is being disconnected
        :return: Reason (str)
        """
        return self.__reason

    def build(self) -> Bin:
        packet_bin = Bin(S2C_CLIENT_DISCONNECT)
        if self.getReason() is not None:
            # Set the reason if the reason is not None encoded in utf-8
            packet_bin.setAttribute("REASON", self.getReason().encode('utf-8'))

        return packet_bin
