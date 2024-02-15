from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import hashlib
from cryptography.hazmat.primitives import serialization
import random
import math

import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin, getAttributeSize
from channel.packet.PacketDimensions import C2S_CHALLENGE_DIMENSIONS


def generateRandomChallenge(paramChallengeLength) -> int:
    randomBits = random.getrandbits(paramChallengeLength)
    return randomBits


class ClientChallengePacket(Packet.Packet):
    def __init__(self, paramChannelID: str, paramClientPublicKey: RSAPublicKey):
        super().__init__(Packet.PacketType.C2S_CHALLENGE, False)

        self.__channelID = paramChannelID
        self.__clientPublicKey = paramClientPublicKey
        self.__challenge = generateRandomChallenge(getAttributeSize(C2S_CHALLENGE_DIMENSIONS, "CHALLENGE"))

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

    def getChallenge(self) -> int:
        return self.__challenge

    def getChallengeBytes(self) -> bytes:
        return self.getChallenge().to_bytes(int(math.ceil(
            getAttributeSize(C2S_CHALLENGE_DIMENSIONS, "CHALLENGE") // 8)),
                                                             byteorder="big")

    def build(self) -> Bin:
        packet_bin = Bin(C2S_CHALLENGE_DIMENSIONS)

        packet_bin.setAttribute("CHANNEL_HASH", self.getChannelIDHash())

        public_key_der = self.getClientPublicKeyBytes()
        packet_bin.setAttribute("PUBLIC_KEY_LENGTH", len(public_key_der))
        packet_bin.setAttribute("CLIENT_PUBLIC_KEY", public_key_der)

        packet_bin.setAttribute("CHALLENGE", self.getChallenge())

        return packet_bin
