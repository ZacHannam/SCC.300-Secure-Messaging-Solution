from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import hashlib
from cryptography.hazmat.primitives import serialization
import random
import math

import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin, getAttributeSize
from channel.packet.PacketDimensions import S2C_CHALLENGE_DIMENSIONS


def generateRandomChallenge(paramChallengeLength) -> int:
    randomBits = random.getrandbits(paramChallengeLength)
    return randomBits


class ServerChallengePacket(Packet.Packet):
    def __init__(self, paramChannelID: str, paramClientPublicKey: RSAPublicKey, paramSignedChallenge: bytes):
        super().__init__(Packet.PacketType.S2C_CHALLENGE, False)

        self.__channelID = paramChannelID
        self.__clientPublicKey = paramClientPublicKey
        self.__signedChallenge = paramSignedChallenge
        self.__challenge = generateRandomChallenge(getAttributeSize(S2C_CHALLENGE_DIMENSIONS, "CHALLENGE"))

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

    def getChallenge(self) -> int:
        return self.__challenge

    def getChallengeBytes(self) -> bytes:
        return self.getChallenge().to_bytes(int(math.ceil(
            getAttributeSize(S2C_CHALLENGE_DIMENSIONS, "CHALLENGE") // 8)),
                                                             byteorder="big")

    def build(self) -> Bin:
        packet_bin = Bin(S2C_CHALLENGE_DIMENSIONS)

        packet_bin.setAttribute("CHANNEL_HASH", self.getChannelIDHash())

        public_key_der = self.getClientPublicKeyBytes()
        packet_bin.setAttribute("PUBLIC_KEY_LENGTH", len(public_key_der))
        packet_bin.setAttribute("SERVER_PUBLIC_KEY", public_key_der)

        packet_bin.setAttribute("CHALLENGE", self.getChallenge())

        packet_bin.setAttribute("SIGNED_CHALLENGE", self.getSignedChallenge())

        return packet_bin
