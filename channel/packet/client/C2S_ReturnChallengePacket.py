import hashlib
import random

import channel.packet.Packet as Packet
from utils.BinarySequencer import Bin
from channel.packet.PacketDimensions import C2S_CHALLENGE_RETURN_DIMENSIONS


def generateRandomChallenge(paramChallengeLength) -> int:
    randomBits = random.getrandbits(paramChallengeLength)
    return randomBits


class ClientChallengeReturnPacket(Packet.Packet):
    def __init__(self, paramChannelID: str, paramSignedChallenge: bytes):
        super().__init__(Packet.PacketType.C2S_CHALLENGE_RETURN, False)

        self.__channelID = paramChannelID
        self.__signedChallenge = paramSignedChallenge

    def getChannelID(self) -> str:
        return self.__channelID

    def getChannelIDHash(self) -> int:
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()
        return int(hex_digest, 16)

    def getSignedChallengeBytes(self) -> bytes:
        return self.__signedChallenge

    def build(self) -> Bin:
        packet_bin = Bin(C2S_CHALLENGE_RETURN_DIMENSIONS)

        packet_bin.setAttribute("CHANNEL_HASH", self.getChannelIDHash())
        packet_bin.setAttribute("SIGNED_CHALLENGE", self.getSignedChallengeBytes())

        return packet_bin
