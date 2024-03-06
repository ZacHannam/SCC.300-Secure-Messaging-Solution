import hashlib

import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_AUTHENTICATE_RETURN_DIMENSIONS


class ClientAuthenticateReturnPacket(Packet.Packet):
    def __init__(self, paramChannelID: str, paramSignedChallenge: bytes):
        """
        The return packet sent to server after the server authenticate packet is received
        :param paramChannelID: Channel ID of server
        :param paramSignedChallenge: Tge signed challenge from the server
        """
        super().__init__(Packet.PacketType.C2S_AUTHENTICATE_RETURN, False)

        self.__channelID: str = paramChannelID  # Channel ID of server
        # Signed challenge which will be the (the server's challenge + plaintext channelID)
        self.__signedChallenge: bytes = paramSignedChallenge

    def getChannelID(self) -> str:
        """
        Get the channel ID
        :return: channel ID (str)
        """
        return self.__channelID

    def getChannelIDHash(self) -> int:
        """
        The channel ID hash sha-256
        :return: channel ID hash (sha-256) (int)
        """
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()
        return int(hex_digest, 16)

    def getSignedChallengeBytes(self) -> bytes:
        """
        The signed challenge which is encrypted using the server's public key
        :return: Signed challenge which will be the (the server's challenge + plaintext channelID)
        """
        return self.__signedChallenge

    def build(self) -> Bin:
        packet_bin = Bin(C2S_AUTHENTICATE_RETURN_DIMENSIONS)

        packet_bin.setAttribute("CHANNEL_HASH", self.getChannelIDHash())  # Channel ID hash
        packet_bin.setAttribute("SIGNED_CHALLENGE", self.getSignedChallengeBytes())  # Signed challenge response

        return packet_bin
