from enum import Enum
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from abc import ABC, abstractmethod
import math
import random
from cryptography.exceptions import InvalidKey, InvalidSignature
from threading import Lock, Event
import cryptography.exceptions

from channel.packet.PacketDimensions import *
import services.Service as Service
from utils.BinarySequencer import Bin, getAttributeSize, getBinSize, getBinSizeBytes
from Properties import PACKET_MAX_SIZE, RSA_KEY_SIZE
from channel.MessengerExceptions import PacketException


class PacketType(Enum):
    """
    List of all the packets       # ( Packet Type, Packet Bin Dimensions)
    """
    C2S_AUTHENTICATE             = (0x01, C2S_AUTHENTICATE_DIMENSIONS)  # Sent to server to challenge / get public key
    S2C_AUTHENTICATE             = (0x02, S2C_AUTHENTICATE_DIMENSIONS)  # Sent to client to challenge / send public key
    C2S_AUTHENTICATE_RETURN      = (0x03, C2S_AUTHENTICATE_RETURN_DIMENSIONS)  # Sent to server to validate challenge

    S2C_REQUEST_USER_DATA        = (0x11, S2C_REQUEST_USER_DATA)  # Ask the client for user data
    C2S_USER_DATA                = (0x12, C2S_USER_DATA)

    S2C_ALIVE                    = (0x21, S2C_ALIVE)  # Ask the client if they are alive
    C2S_ALIVE_RESPONSE           = (0x22, C2S_ALIVE_RESPONSE)  # Respond to the server if they are alive

    S2C_USER_JOIN                = (0x31, S2C_USER_JOIN)  # Sent to client when user joins
    S2C_USER_LEAVE               = (0x32, S2C_USER_LEAVE)  # Sent to all clients when someone leaves channel

    S2C_TEXT_MESSAGE             = (0x41, S2C_TEXT_MESSAGE)  # Sent to client to send a message
    C2S_TEXT_MESSAGE             = (0x42, C2S_TEXT_MESSAGE)  # Sent to server to send a message

    S2C_INFO_MESSAGE             = (0x51, S2C_INFO_MESSAGE)  # Send info to a client

    S2C_CLIENT_DISCONNECT        = (0x61, S2C_CLIENT_DISCONNECT)  # Sent to client to kick them from the server
    C2S_USER_LEAVE               = (0x62, C2S_USER_LEAVE)  # Sent to server when user leaves


# Enumeration of all the packet, 0x## -> PacketType
PACKET_TYPE_ENUMERATION = dict([(packet.value[0], packet) for packet in PacketType])

# Max size of a packet in bytes
PACKET_MAX_SIZE_BYTES = int(math.ceil(PACKET_MAX_SIZE / 8))

# Bin for packet content when encrypted
PACKET_BIN_ENCRYPTED = [("CONTENT", 4040),      # Content sent
                        ("PACKET_AUTH", 16),    # Header ID
                        ("PACKET_SIZE", 16),    # Number of packets sent
                        ("PACKET_NUMBER", 16),  # Packet number in sequence
                        ("PACKET_ID", 8)]       # Type of packet

# Bin for when a packet is unencrypted
PACKET_BIN_UNENCRYPTED = [("CONTENT", 8136),      # Content sent
                          ("PACKET_AUTH", 16),    # Header ID
                          ("PACKET_SIZE", 16),    # Number of packets sent
                          ("PACKET_NUMBER", 16),  # Packet number in sequence
                          ("PACKET_ID", 8)]       # Type of packet


class Packet(ABC):
    def __init__(self, paramPacketType: PacketType, paramEncrypted: bool):
        """
        Abstract packet class
        :param paramPacketType: Type of the packet
        :param paramEncrypted: If the packet is encrypted
        """
        self.__packetType: PacketType = paramPacketType  # packet type
        self.__isEncrypted: bool = paramEncrypted  # If packet is encrypted

    """
            Getter Methods
    """

    def getPacketType(self) -> PacketType:
        """
        Get the packet type
        :return: PacketType
        """
        return self.__packetType

    def isEncrypted(self) -> bool:
        """
        If the packet is encrypted
        :return: packet encrypted (bool)
        """
        return self.__isEncrypted


    """
            Abstract Methods
    """

    @abstractmethod
    def build(self) -> Bin:
        raise NotImplementedError("build method not implemented")


    """
            Packet Conversion
    """

    def getPackets(self) -> tuple[bool, list[Bin]]:
        """
        Split all the packets into the correct sizes and headers
        :return: tuple[is Encrypted, list[Packet Binaries])
        """

        # 1) Choose the correct bin based on if its encrypted
        selectedBin = PACKET_BIN_ENCRYPTED if self.isEncrypted() else PACKET_BIN_UNENCRYPTED
        assert getBinSize(selectedBin) == (PACKET_MAX_SIZE // 2 if self.isEncrypted() else PACKET_MAX_SIZE)

        # 2) Get the attributes of the bin
        contentLength, authSize, maxPacketSize = getAttributeSize(selectedBin, "CONTENT", "PACKET_AUTH", "PACKET_SIZE")

        # 3) Create a random packet id
        packet_auth = random.getrandbits(authSize)

        # 4) Build the packet, get the bin and convert it to an int, to be transferred back into that bin later
        packet = self.build()

        # Check that the dimensions are what is expected of the packet
        if packet.getDimensions() != self.getPacketType().value[1]:
            raise PacketException(None, PacketException.PACKET_INCORRECT_DIMENSIONS)  # Raise exception

        packet_result = packet.getResult()
        packet_length = packet.getBinSize()

        # 5) Split the built packet into multiple packet contents that fit the bin
        packets_results = [(packet_result >> (i * contentLength)) & ((2 ** contentLength) - 1)
                           for i in range(math.ceil(packet_length / contentLength) - 1, -1, -1)]
        if not len(packets_results):
            packets_results = [0]  # Make sure at least one packet is sent even when there is no content i.e S2C_Alive


        if len(packets_results) >= (2 ** maxPacketSize):  # Check that there are enough sequence IDs available
            raise PacketException(None, PacketException.CONTENT_TOO_LARGE)  # Raise exception

        # 6) Create the packet binaries
        packetBins = [Bin(PACKET_BIN_ENCRYPTED if self.isEncrypted() else PACKET_BIN_UNENCRYPTED)
                      for _ in packets_results]

        # 6.1) Attach the content and headers to the packet
        for index, (packet_bin, packet_result) in enumerate(zip(packetBins, packets_results)):
            packet_bin.setAttribute("CONTENT", packet_result)
            packet_bin.setAttribute("PACKET_AUTH", packet_auth)
            packet_bin.setAttribute("PACKET_SIZE", len(packetBins))
            packet_bin.setAttribute("PACKET_NUMBER", index + 1)
            packet_bin.setAttribute("PACKET_ID", self.getPacketType().value[0])

        return self.isEncrypted(), packetBins


class PacketSender(Service.ServiceThread):
    def __init__(self, paramPacket: Packet, paramConnection: socket.socket, paramClientPublicKey: RSAPublicKey | None):
        """
        Used to send a packet to the other socket
        :param paramPacket: Packet being sent
        :param paramConnection: Connection being sent to
        :param paramClientPublicKey: The public key of the client/server being sent to
        """
        super().__init__(Service.ServiceType.SEND_PACKET)

        self.__packet: Packet = paramPacket  # Packet being sent
        self.__connection: socket.socket = paramConnection  # Connection to send packet to
        self.__clientPublicKey: RSAPublicKey | None = paramClientPublicKey  # Their public key if available


    """
            Getter Methods
    """

    def getPacket(self) -> Packet:
        """
        Get the packet being sent
        :return: Packet
        """
        return self.__packet

    def getConnection(self) -> socket.socket:
        """
        Connection to send packet to
        :return: Connection (socket.socket)
        """
        return self.__connection

    def getClientPublicKey(self) -> RSAPublicKey | None:
        """
        Connection being sent to public key if available
        :return: public key or None
        """
        return self.__clientPublicKey

    def run_safe(self):
        """
        Main run method for thread, ran safely
        :return:
        """

        # 1) Convert the packets into send-able packets
        isEncrypted, packetBins = self.getPacket().getPackets()

        # 2) Validate that the encryption is there if its necessary
        if not ((isEncrypted and self.getClientPublicKey() is not None) or not isEncrypted):
            raise PacketException(None, PacketException.PACKET_EXPECTED_ENCRYPTION)  # Raise exception

        # 3) Encrypt full packet content and headers
        packetsToSend = []  # Packets to be sent
        if isEncrypted:
            for packet in packetBins:

                # Encrypt all packets
                resultBytes = packet.getResultBytes()
                assert len(resultBytes) == (PACKET_MAX_SIZE_BYTES // 2)  # Make sure the packets fit (should not fail)

                # Split packets to fit half key size (for padding reasons)
                # and encrypt individually (Can only encrypt up to length)
                key_size_bytes = RSA_KEY_SIZE // 8  # Will always be a multiple of 8
                half_key_size = key_size_bytes // 2  # Will always be a multiple of 2

                # Doing this will result in the correct content
                resultBytes = [resultBytes[index * half_key_size: (index + 1) * half_key_size]
                               for index in range(math.ceil(len(resultBytes) / half_key_size))]

                # Should always happen if the packets are correctly encoded
                assert len(resultBytes) == 2 and len(resultBytes[0]) == len(resultBytes[1]) == half_key_size

                # Build the encrypted packet data
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
                packetsToSend.append(packetData)  # Add packet to be sent

        else:  # If packet is not encrypted
            for packet in packetBins:
                packetData = packet.getResultBytes(sizeBytes=PACKET_MAX_SIZE_BYTES)

                assert len(packetData) == PACKET_MAX_SIZE_BYTES
                packetsToSend.append(packetData)  # Don't need to encrypt the packet so add it to be sent

        try:
            for packetData in packetsToSend:
                self.getConnection().sendall(packetData)  # Send the packet to the socket
        except BrokenPipeError:
            raise PacketException(None, PacketException.FAILED_TO_SEND_PACKET)  # Raise exception
            # If there is a broken pipe simply just stop trying. It is probably where the client
            # closes the connection before we know. They wont be sent after alive checker removes them


class PacketCollector(Service.ServiceThread):
    def __init__(self, paramSocket: socket.socket, paramPrivateKey: RSAPrivateKey, paramStopEvent: Event):
        """
        Packet collector collects all incoming packets on socket and puts them together
        :param paramSocket: The socket to listen to
        :param paramPrivateKey: The private key to decrypt the packets
        :param paramStopEvent: Stop event for the client/server using the packet collector
        """
        super().__init__(Service.ServiceType.PACKET_COLLECTOR)

        self.__privateKey: RSAPrivateKey = paramPrivateKey  # Private key to decrypt
        self.__socket: socket.socket = paramSocket  # Socket to listen to
        self.__stop: Event = paramStopEvent  # Stop event

        # To be initialised
        # (packetAuth, packetType, packetSize) -> [(packetNumber, packetContent), ...]
        # Packets collected but not finalised
        self.__packets: dict[tuple[int, PacketType, int], list[tuple[int, int]]] = {}

        # (packetType, packetBin)
        self.__finalisedPacket: list[tuple[PacketType, Bin]] = []  # Finalised packets

        self.__finalisedPacketLock = Lock()  # Async lock for popping and adding finalised packets


    """
            Getter Methods
    """

    def getSocket(self) -> socket.socket:
        """
        Get the socket listened to
        :return: socket listened to (socket.socket)
        """
        return self.__socket

    def getPrivateKey(self) -> RSAPrivateKey:
        """
        Server/Client private key to decrypt data
        :return: client/server private key (RSAPrivateKey)
        """
        return self.__privateKey

    def getPackets(self) -> dict[tuple[int, PacketType, int], list[tuple[int, int]]]:
        """
        Get the collected packets that are not finalised
        :return: (packetAuth, packetType, packetSize) -> [(packetNumber, packetContent), ...]
        """
        return self.__packets

    def getFinalisedPackets(self) -> list[tuple[PacketType, Bin]]:
        """
        Finalised packets that are ready to be used
        :return: (packetType, packetBin: Using packet type dimensions)
        """
        return self.__finalisedPacket

    def getFinalisedPacketsLock(self) -> Lock:
        """
        Get the finalised packet lock
        :return: Finalised packet lock (Lock)
        """
        return self.__finalisedPacketLock

    def getStopEvent(self) -> Event:
        """
        Get the stop event
        :return: stop event (Event)
        """
        return self.__stop


    """
            Get Packet Methods
    """

    def awaitPacket(self, packet_type: PacketType | None = None) -> None | tuple[PacketType, Bin]:
        """
        Wait for a certain type of packet
        :param packet_type: packet type to be collected
        :return: None if stopped or the packet collected (tuple[PacketType, Bin])
        """
        awaitedPacket = None  # Define the awaited packet as None
        while (not self.getStopEvent().is_set()) and \
                ((awaitedPacket := self.getNextPacket(packet_type=packet_type)) is None):  # Get the awaited packet
            continue  # Continue waiting
        return None if self.getStopEvent().is_set() else awaitedPacket

    def getNextPacket(self, packet_type: PacketType | None = None) -> None | tuple[PacketType, Bin]:
        """
        Get the next packet from the finalised packets
        :param packet_type: None if general packet or the packet type to get
        :return: None if there is no packet available or the packet searched for
        """
        with self.getFinalisedPacketsLock():  # Use the finalised packet lock for concurrency issues
            if packet_type is None:  # If the packet type is not specified get the first packet
                return self.getFinalisedPackets().pop(0) if len(self.getFinalisedPackets()) > 0 else None

            for index, (packetType, _) in enumerate(self.getFinalisedPackets()):
                if packetType == packet_type:
                    return self.getFinalisedPackets().pop(index)

            return None  # Return none if there is no packet found

    def run_safe(self):
        while not self.getStopEvent().is_set():  # Run until it is stopped
            # attempt decrypt on data if there is a public key

            try:
                if len((data := self.getSocket().recv(PACKET_MAX_SIZE_BYTES))) != PACKET_MAX_SIZE_BYTES:
                    continue
            except OSError:  # Socket closed so stop packet collector and everything else
                if not self.getStopEvent().is_set():  # If the stop event is not set then its unexpected
                    raise PacketException(self.getStopEvent(), PacketException.PACKET_COLLECT_SOCKET_CLOSED)
                return

            # If the private key is not none then attempt to decrypt
            if self.getPrivateKey() is not None:

                try:  # Will throw error if it can't be decrypted so assume its just not encrypted

                    # Split packets to fit key size
                    # and encrypt individually (Can only encrypt up to length)
                    key_size_bytes = RSA_KEY_SIZE // 8  # Will always be a multiple of 8

                    # Re split the data
                    data_split =  [data[index * key_size_bytes: (index + 1) * key_size_bytes]
                                   for index in range(math.ceil(len(data) / key_size_bytes))]

                    # Should always happen if the packets are correctly encoded
                    assert len(data_split) == 2 and len(data_split[0]) == len(data_split[1]) == key_size_bytes

                    # Decrypt each part of the packet
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
                    data = finalisedData  # Return the finalised collected unencrypted data

                except (InvalidKey, InvalidSignature, ValueError, AssertionError,
                        cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
                    pass  # Attempt to keep going thinking its not encrypted

            if len(data) == getBinSizeBytes(PACKET_BIN_ENCRYPTED):  # Check if its the encrypted size
                packet_bin = Bin(PACKET_BIN_ENCRYPTED, population=data)  # Put it in an encrypted packet bin
            elif len(data) == getBinSizeBytes(PACKET_BIN_UNENCRYPTED):  # Check if its unencrypted size
                packet_bin = Bin(PACKET_BIN_UNENCRYPTED, population=data)  # Put it in an unencrypted packet bin
            else:
                # Should not happen normally, but just in case if its a undefined length
                raise PacketException(self.getStopEvent(), PacketException.PACKET_INCORRECT_SIZE)

            packetContent: int   = packet_bin.getAttribute("CONTENT")
            packetAuth: int      = packet_bin.getAttribute("PACKET_AUTH")
            packetSize: int      = packet_bin.getAttribute("PACKET_SIZE")
            packetNumber: int    = packet_bin.getAttribute("PACKET_NUMBER")
            packetID: int        = packet_bin.getAttribute("PACKET_ID")

            # 1) Validate the packet type
            packetType = getPacketTypeFromPacketID(packetID)
            if packetType is None:
                # Raise unexpected packet type
                raise PacketException(self.getStopEvent(), PacketException.UNEXPECTED_PACKET_TYPE)

            # 2) If the packet size is only one then it can go straight into the finalised packets as there is no
            # need to wait for more packets to complete it
            if packetSize == 1:
                packetDimensions = packetType.value[1]  # Get the dimensions from the packet type
                packet_bin = Bin(packetDimensions, population=packetContent)  # Fit into the correct packet bin

                self.getFinalisedPackets().append((packetType, packet_bin))  # Add the finalised packet
                continue  # Finish cycle as don't need to check for another packet

            # 3) Define the key and the value for the packet list (not finalised)
            key = (packetAuth, packetType, packetSize)
            value = (packetNumber, packetContent)

            # 4) Check if another packet already exists so it can be pieced together
            if key in self.getPackets():
                self.getPackets().get(key).append(value)  # Add the value to the packet list
            else:
                self.getPackets()[key] = [value]  # Start the list of values

            # 5) Check if there are enough packets to satisfy the packet size (Finished collecting packets)
            if len(self.getPackets().get(key)) == packetSize:
                contents = dict(self.getPackets().get(key))  # Collect the contents

                totalContents = 0  # Initiate the content (int)
                for index in range(packetSize):  # Iterate using packet number instead of order
                    if not (index + 1) in contents:
                        # Raise error as a packet has an incorrect sequence id
                        raise PacketException(self.getStopEvent(), PacketException.PACKET_IDENTITY_INCORRECT)

                    # Compile the contents into one long binary content
                    content = contents.get(index + 1)
                    totalContents = (totalContents << packet_bin.getAttributeSize("CONTENT")) + content

                # Add the finalised packet with content adjusted into the packet dimensions
                packetDimensions = packetType.value[1]  # Get the packet dimensions
                packet_bin = Bin(packetDimensions, population=totalContents)  # Fill out the bin dimensions
                self.getFinalisedPackets().append((packetType, packet_bin))
                del self.getPackets()[key]


def getPacketTypeFromPacketID(paramPacketType: int) -> PacketType | None:
    """
    Get the packet type from the packet id, enumeration
    :param paramPacketType: Packet Type ID
    :return: Packet Type or None if its not found
    """
    for packetType in PacketType:
        if packetType.value[0] == paramPacketType:
            return packetType

    return None


def getPacketDimensionsFromPacketType(paramPacketType: int) -> list | None:
    """
    Get the packet dimensions from the packet type
    :param paramPacketType:
    :return: packet dimensions or None if not found
    """
    for packetType in PacketType:
        if packetType.value[0] == paramPacketType:
            return packetType.value[1]

    return None


def sendPacket(paramPacket: Packet, paramConnection: tuple[socket.socket, RSAPublicKey] |
               list[tuple[socket.socket, RSAPublicKey]]) -> None:
    """
    Send a packet to the connection
    :param paramPacket: packet to be sent
    :param paramConnection: socket and public key to send packet to or list of socket and public keys
    :return: None
    """
    if isinstance(paramConnection, tuple):  # Check if only one connection
        connection, public_key = paramConnection  # unpack the connection
        packetSender = PacketSender(paramPacket, connection, public_key)
        packetSender.start()  # Start asynchronous packet sender thread

    else:
        for connection, public_key in paramConnection:
            packetSender = PacketSender(paramPacket, connection, public_key)
            packetSender.start()  # Start asynchronous packet sender thread
