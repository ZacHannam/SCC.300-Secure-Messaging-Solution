from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import hashlib
from cryptography.hazmat.primitives import serialization
import os

import channel.Packet as Packet
from utils.BinarySequencer import Bin
from channel.PacketDimensions import C2S_AUTHENTICATE_DIMENSIONS


class ClientAuthenticatePacket(Packet.Packet):
    """
    Client authenticate packet sent to the server to authenticate client
    """
    def __init__(self, paramChannelID: str, paramClientPublicKey: RSAPublicKey):
        super().__init__(Packet.PacketType.C2S_AUTHENTICATE, False)

        self.__channelID: str = paramChannelID
        self.__clientPublicKey: RSAPublicKey = paramClientPublicKey
        self.__randomChallenge: bytes = generateRandomChallenge()

    def getChannelID(self) -> str:
        """
        Get the channel ID of the server connected to
        :return: channel id (str)
        """
        return self.__channelID

    def getChannelIDHash(self) -> int:
        """
        Hash of the channel ID sha-256
        :return: channel id hash as int
        """
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()
        return int(hex_digest, 16)

    def getClientPublicKey(self) -> RSAPublicKey:
        """
        Get the client's public key
        :return: client public key (RSAPublicKey)
        """
        return self.__clientPublicKey

    def getClientPublicKeyBytes(self) -> bytes:
        """
        Return the public key as bytes using DER encoding
        :return: Public Key (DER Encoded) (bytes)
        """
        public_key_der = self.getClientPublicKey().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key_der

    def getChallenge(self) -> bytes:
        """
        Return the random challenge for the server to encrypt
        :return:
        """
        return self.__randomChallenge

    def build(self) -> Bin:
        packet_bin = Bin(C2S_AUTHENTICATE_DIMENSIONS)

        packet_bin.setAttribute("CHANNEL_HASH", self.getChannelIDHash())  # Channel ID hashed

        public_key_der = self.getClientPublicKeyBytes()
        packet_bin.setAttribute("CLIENT_PUBLIC_KEY", public_key_der)  # The client's public key

        packet_bin.setAttribute("CHALLENGE", self.getChallenge())  # Challenge for the server

        return packet_bin


def generateRandomChallenge() -> bytes:
    """
    Generate a random challenge for the server
    :return: Random challenge (bytes)
    """
    return b'\01' + os.urandom(32)  # If it starts with \00 then it causes errors with bins
