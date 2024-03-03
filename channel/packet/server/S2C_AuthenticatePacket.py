from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import hashlib
from cryptography.hazmat.primitives import serialization
import os

import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import S2C_AUTHENTICATE_DIMENSIONS


def generateRandomChallenge() -> bytes:
    return os.urandom(32)


class ServerAuthenticatePacket(Packet.Packet):
    def __init__(self, paramChannelID: str, paramClientPublicKey: RSAPublicKey, paramSignedChallenge: bytes):
        super().__init__(Packet.PacketType.S2C_AUTHENTICATE, False)

        self.__channelID = paramChannelID
        self.__clientPublicKey = paramClientPublicKey
        self.__signedChallenge = paramSignedChallenge
        self.__randomChallenge = generateRandomChallenge()

    def getChannelID(self) -> str:
        return self.__channelID

    def getChannelIDHash(self) -> int:
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()
        return int(hex_digest, 16)

    def getClientPublicKey(self) -> RSAPublicKey:
        return self.__clientPublicKey

    def getClientPublicKeyBytes(self) -> bytes:
        public_key_der = self.getClientPublicKey().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key_der

    def getSignedChallenge(self) -> bytes:
        return self.__signedChallenge

    def getChallenge(self) -> bytes:
        return self.__randomChallenge

    def build(self) -> Bin:
        packet_bin = Bin(S2C_AUTHENTICATE_DIMENSIONS)

        packet_bin.setAttribute("CHANNEL_HASH", self.getChannelIDHash())

        public_key_der = self.getClientPublicKeyBytes()
        packet_bin.setAttribute("PUBLIC_KEY_LENGTH", len(public_key_der))
        packet_bin.setAttribute("SERVER_PUBLIC_KEY", public_key_der)

        packet_bin.setAttribute("CHALLENGE", self.getChallenge())

        packet_bin.setAttribute("SIGNED_CHALLENGE", self.getSignedChallenge())

        return packet_bin
