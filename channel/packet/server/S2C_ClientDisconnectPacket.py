import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import S2C_CLIENT_DISCONNECT


class ClientDisconnectPacket(Packet.Packet):
    def __init__(self, paramReason: str | None):
        super().__init__(Packet.PacketType.S2C_CLIENT_DISCONNECT, True)

        self.__reason = paramReason

    def getReason(self) -> str | None:
        return self.__reason

    def build(self) -> Bin:
        packet_bin = Bin(S2C_CLIENT_DISCONNECT)
        if self.getReason() is not None:
            packet_bin.setAttribute("REASON", self.getReason().encode('utf-8'))

        return packet_bin
