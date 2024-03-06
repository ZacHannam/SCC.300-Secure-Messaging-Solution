from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import hashlib
from cryptography.hazmat.primitives import serialization
import os

import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import S2C_AUTHENTICATE_DIMENSIONS


class ServerAuthenticatePacket(Packet.Packet):
    def __init__(self, paramChannelID: str, paramClientPublicKey: RSAPublicKey, paramSignedChallenge: bytes):
        """
        Sent to the client to authenticate the server
        :param paramChannelID: Channel ID of the server
        :param paramClientPublicKey: The public key of the client
        :param paramSignedChallenge: The signed challenge from the client
        """
        super().__init__(Packet.PacketType.S2C_AUTHENTICATE, False)

        self.__channelID: str = paramChannelID  # Channel ID of server / client
        self.__clientPublicKey: RSAPublicKey = paramClientPublicKey  # Client's public key
        self.__signedChallenge: bytes = paramSignedChallenge  # Signed challenge from the client
        self.__randomChallenge: bytes = generateRandomChallenge()  # Random challenge for the client

    def getChannelID(self) -> str:
        """
        The channel ID of the server and client
        :return: Channel ID (str)
        """
        return self.__channelID

    def getChannelIDHash(self) -> int:
        """
        The hashed channel ID of the server and client
        :return: Hashed channel ID (sha-256) (int)
        """
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()
        return int(hex_digest, 16)

    def getClientPublicKey(self) -> RSAPublicKey:
        """
        The client's public key
        :return: Clients public key (RSAPublicKey)
        """
        return self.__clientPublicKey

    def getClientPublicKeyBytes(self) -> bytes:
        """
        Client's public key encoded in DER format
        :return: Client Public Key (DER) (bytes)
        """
        public_key_der = self.getClientPublicKey().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key_der

    def getSignedChallenge(self) -> bytes:
        """
        Signed challenge from the client
        :return:
        """
        return self.__signedChallenge

    def getChallenge(self) -> bytes:
        """
        Challenge for the client
        :return: Challenge (bytes)
        """
        return self.__randomChallenge

    def build(self) -> Bin:
        packet_bin = Bin(S2C_AUTHENTICATE_DIMENSIONS)

        packet_bin.setAttribute("CHANNEL_HASH", self.getChannelIDHash())  # Set channel hash

        public_key_der = self.getClientPublicKeyBytes()
        packet_bin.setAttribute("PUBLIC_KEY_LENGTH", len(public_key_der))  # Set length of public key
        packet_bin.setAttribute("SERVER_PUBLIC_KEY", public_key_der)  # Set the public key bytes

        packet_bin.setAttribute("CHALLENGE", self.getChallenge())  # Set challenge for the client

        # Set the signed challenge from the client
        packet_bin.setAttribute("SIGNED_CHALLENGE", self.getSignedChallenge())

        return packet_bin


def generateRandomChallenge() -> bytes:
    """
    Generate a random challenge for the client
    :return: Random challenge (bytes)
    """
    return os.urandom(32)
