from enum import Enum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from abc import ABC, abstractmethod
import math
import random
from cryptography.exceptions import InvalidKey, InvalidSignature
from threading import Lock
import traceback

from channel.packet.PacketDimensions import *
import services.Service as Service
from utils.BinarySequencer import Bin, getAttributeSize, getBinSize, getBinSizeBytes
from Properties import PACKET_MAX_SIZE


class PacketType(Enum):
    C2S_AUTHENTICATE = (0x01, C2S_AUTHENTICATE_DIMENSIONS)  # Sent to server to challenge / get public key
    S2C_AUTHENTICATE = (0x02, S2C_AUTHENTICATE_DIMENSIONS)  # Sent to client to challenge / send public key
    C2S_AUTHENTICATE_RETURN = (0x03, C2S_AUTHENTICATE_RETURN_DIMENSIONS)  # Sent to server to validate challenge

    S2C_REQUEST_USER_DATA = (0x11, S2C_REQUEST_USER_DATA)  # Ask the client for user data
    C2S_USER_DATA = (0x12, C2S_USER_DATA)

    S2C_ALIVE = (0x21, S2C_ALIVE)  # Ask the client if they are alive
    C2S_ALIVE_RESPONSE = (0x22, C2S_ALIVE_RESPONSE)  # Respond to the server if they are alive

    S2C_USER_JOIN = (0x31, S2C_USER_JOIN)  # Sent to client when user joins
    S2C_USER_LEAVE = (0x32, S2C_USER_LEAVE)  # Sent to all clients when someone leaves channel

    S2C_TEXT_MESSAGE = (0x41, S2C_TEXT_MESSAGE)  # Sent to client to send a message
    C2S_TEXT_MESSAGE = (0x42, C2S_TEXT_MESSAGE)  # Sent to server to send a message

    S2C_INFO_MESSAGE = (0x51, S2C_INFO_MESSAGE)  # Send info to a client

    S2C_CLIENT_DISCONNECT = (0x61, S2C_CLIENT_DISCONNECT)  # Sent to client to kick them from the server
    C2S_USER_LEAVE = (0x62, C2S_USER_LEAVE)  # Sent to server when user leaves


PACKET_TYPE_ENUMERATION = dict([(packet.value[0], packet) for packet in PacketType])
PACKET_TYPE_SIZE = 8
PACKET_MAX_SIZE_BYTES = int(math.ceil(PACKET_MAX_SIZE / 8))

PACKET_BIN_ENCRYPTED = [("CONTENT", 4040),
                        ("PACKET_AUTH", 16),
                        ("PACKET_SIZE", 16),
                        ("PACKET_NUMBER", 16),
                        ("PACKET_ID", 8)]

PACKET_BIN_UNENCRYPTED = [("CONTENT", 8136),
                          ("PACKET_AUTH", 16),
                          ("PACKET_SIZE", 16),
                          ("PACKET_NUMBER", 16),
                          ("PACKET_ID", 8)]


class Packet(ABC):
    def __init__(self, paramPacketType: PacketType, paramEncrypted: bool):
        self.__packetType = paramPacketType
        self.__isEncrypted = paramEncrypted

    @abstractmethod
    def build(self) -> Bin:
        raise NotImplementedError("build method not implemented")

    def getPacketType(self) -> PacketType:
        return self.__packetType

    def isEncrypted(self) -> bool:
        return self.__isEncrypted

    def getPackets(self) -> tuple[bool, list[Bin]]:

        selectedBin = PACKET_BIN_ENCRYPTED if self.isEncrypted() else PACKET_BIN_UNENCRYPTED
        assert getBinSize(selectedBin) == (PACKET_MAX_SIZE // 2 if self.isEncrypted() else PACKET_MAX_SIZE)

        contentLength, authSize, maxPacketSize = getAttributeSize(selectedBin, "CONTENT", "PACKET_AUTH", "PACKET_SIZE")

        packet_auth = random.getrandbits(authSize)

        packet = self.build()
        packet_result = packet.getResult()
        packet_length = packet.getBinSize()

        packets_results = [(packet_result >> (i * contentLength)) & ((2 ** contentLength) - 1)
                           for i in range(math.ceil(packet_length / contentLength) - 1, -1, -1)]
        if not len(packets_results):
            packets_results = [0]

        assert len(packets_results) < (2 ** maxPacketSize)  # <=  (2**maxPacketSize)-1

        packetBins = [Bin(PACKET_BIN_ENCRYPTED if self.isEncrypted() else PACKET_BIN_UNENCRYPTED)
                      for _ in packets_results]

        for index, (packet_bin, packet_result) in enumerate(zip(packetBins, packets_results)):
            packet_bin.setAttribute("CONTENT", packet_result)
            packet_bin.setAttribute("PACKET_AUTH", packet_auth)
            packet_bin.setAttribute("PACKET_SIZE", len(packetBins))
            packet_bin.setAttribute("PACKET_NUMBER", index + 1)
            packet_bin.setAttribute("PACKET_ID", self.getPacketType().value[0])

        return self.isEncrypted(), packetBins


class PacketSender(Service.ServiceThread):
    def __init__(self, paramPacket: Packet, paramConnection, paramClientPublicKey: RSAPublicKey):
        super().__init__(Service.ServiceType.SEND_PACKET)

        self.__packet = paramPacket
        self.__connection = paramConnection
        self.__clientPublicKey = paramClientPublicKey

    def getPacket(self) -> Packet:
        return self.__packet

    def getConnection(self):
        return self.__connection

    def getClientPublicKey(self) -> RSAPublicKey:
        return self.__clientPublicKey

    def run(self):

        isEncrypted, packetBins = self.getPacket().getPackets()
        assert (isEncrypted and self.getClientPublicKey() is not None) or not isEncrypted

        packetsToSend = []
        if isEncrypted:
            for packet in packetBins:

                resultBytes = packet.getResultBytes()
                assert len(resultBytes) == (PACKET_MAX_SIZE_BYTES // 2)

                resultBytes = [resultBytes[:256], resultBytes[256:]]
                assert len(resultBytes[0]) == len(resultBytes[1])

                packetData = b''
                for resultByteSplit in resultBytes:
                    packetData += self.getClientPublicKey().encrypt(
                        resultByteSplit,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA512()),
                            algorithm=hashes.SHA512(),
                            label=None
                        )
                    )

                assert len(packetData) == PACKET_MAX_SIZE_BYTES
                packetsToSend.append(packetData)

        else:
            for packet in packetBins:
                packetData = packet.getResultBytes(sizeBytes=PACKET_MAX_SIZE_BYTES)

                assert len(packetData) == PACKET_MAX_SIZE_BYTES
                packetsToSend.append(packetData)

        try:
            for packetData in packetsToSend:
                self.getConnection().sendall(packetData)
        except BrokenPipeError:
            pass  # If there is a broken pipe simply just stop trying. It is probably where the client
            # closes the connection before we know. They wont be sent after alive checker removes them


class PacketCollector(Service.ServiceThread):
    def __init__(self, paramSocket, paramPrivateKey, paramStopEvent):
        super().__init__(Service.ServiceType.PACKET_COLLECTOR)

        self.__privateKey = paramPrivateKey
        self.__socket = paramSocket
        self.__packets = {}  # (packetAuth, packetType, packetSize) -> [(packetNumber, packetContent), ...]
        self.__finalisedPacket = []  # (packetType, packetBin)
        self.__finalisedPacketLock = Lock()
        self.__stop = paramStopEvent

    def getSocket(self):
        return self.__socket

    def getPrivateKey(self) -> RSAPrivateKey:
        return self.__privateKey

    def getPackets(self) -> dict:
        return self.__packets

    def getFinalisedPackets(self) -> list:
        return self.__finalisedPacket

    def __getFinalisedPacketsLock(self) -> Lock:
        return self.__finalisedPacketLock

    def awaitPacket(self, packet_type=None) -> None | tuple:
        while (not self.__stop.is_set()) and ((packet := self.getNextPacket(packet_type=packet_type)) is None):
            continue
        return packet

    def getNextPacket(self, packet_type=None) -> None | tuple:
        with self.__getFinalisedPacketsLock():
            if packet_type is None:
                return self.getFinalisedPackets().pop(0) if len(self.getFinalisedPackets()) > 0 else None

            for index, packet in enumerate(self.getFinalisedPackets()):
                if packet[0] == packet_type:
                    return self.getFinalisedPackets().pop(index)

            return None

    def run(self):
        try:
            while not self.__stop.is_set():
                # attempt decrypt on data if there is a public key

                try:
                    if len((data := self.getSocket().recv(PACKET_MAX_SIZE_BYTES))) != PACKET_MAX_SIZE_BYTES:
                        continue
                except OSError:  # Socket closed so can return this
                    return

                if self.getPrivateKey() is not None:

                    try:
                        data_split = [data[:512], data[512:]]
                        assert len(data_split[0]) == len(data_split[1])

                        finalisedData = b''
                        for encryptedData in data_split:
                            finalisedData += self.getPrivateKey().decrypt(
                                encryptedData,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                    algorithm=hashes.SHA512(),
                                    label=None
                                )
                            )
                        assert len(finalisedData) == PACKET_MAX_SIZE_BYTES // 2
                        data = finalisedData
                    except (InvalidKey, InvalidSignature, ValueError):
                        pass

                if len(data) == getBinSizeBytes(PACKET_BIN_ENCRYPTED):
                    packet_bin = Bin(PACKET_BIN_ENCRYPTED, population=data)
                elif len(data) == getBinSizeBytes(PACKET_BIN_UNENCRYPTED):
                    packet_bin = Bin(PACKET_BIN_UNENCRYPTED, population=data)
                else:
                    raise RuntimeError(f"Failed to decode packet of length ({len(data)})")

                packetContent, packetAuth, packetSize, packetNumber, packetID = packet_bin. \
                    getAttribute("CONTENT", "PACKET_AUTH", "PACKET_SIZE", "PACKET_NUMBER", "PACKET_ID")

                packetType = getPacketTypeFromPacketID(packetID)
                if packetType is None:
                    continue

                if packetSize == 1:
                    packetDimensions = packetType.value[1]
                    packet_bin = Bin(packetDimensions, population=packetContent)

                    self.getFinalisedPackets().append((packetType, packet_bin))
                    continue

                key = (packetAuth, packetType, packetSize)
                value = (packetNumber, packetContent)
                if key in self.getPackets():
                    self.getPackets().get(key).append(value)
                else:
                    self.getPackets()[key] = [value]

                if len(self.getPackets().get(key)) == packetSize:

                    contents = dict(self.getPackets().get(key))
                    totalContents, packetsScanned = 0, 0
                    for index in range(packetSize):
                        if not (index + 1) in contents:
                            break

                        content = contents.get(index + 1)
                        totalContents = (totalContents << packet_bin.getAttributeSize("CONTENT")) + content
                        packetsScanned += 1

                    if packetsScanned == packetSize:
                        packetDimensions = packetType.value[1]
                        packet_bin = Bin(packetDimensions, population=totalContents)
                        self.getFinalisedPackets().append((packetType, packet_bin))
                    del self.getPackets()[key]

        except Exception:
            traceback.print_exc()


def getPacketTypeFromPacketID(paramPacketType: int) -> PacketType | None:
    for packetType in PacketType:
        if packetType.value[0] == paramPacketType:
            return packetType

    return None


def getPacketDimensionsFromPacketType(paramPacketType: int) -> list | None:
    for packetType in PacketType:
        if packetType.value[0] == paramPacketType:
            return packetType.value[1]

    return None


def sendPacket(paramPacket: Packet, paramConnection):
    if isinstance(paramConnection, tuple):
        connection, public_key = paramConnection
        packetSender = PacketSender(paramPacket, connection, public_key)
        packetSender.start()

    else:
        for connection, public_key in paramConnection:
            packetSender = PacketSender(paramPacket, connection, public_key)
            packetSender.start()
