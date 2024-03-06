import hashlib
import socket
import time
from threading import Event

import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding

from Properties import LEGAL_DISPLAY_NAME_CHARACTERS, CHANNEL_USER_DISPLAY_NAME_MAX, MAXIMUM_MESSAGE_SIZE
from utils.MessengerExceptions import ServerException
from channel.Packet import PacketCollector, Packet, sendPacket, PacketType
from channel.server.packet.S2C_AuthenticatePacket import ServerAuthenticatePacket
from channel.server.packet.S2C_ClientDisconnectPacket import ClientDisconnectPacket
from channel.server.packet.S2C_InfoMessagePacket import InfoMessagePacket
from channel.server.packet.S2C_RequestUserDataPacket import RequestUserData
from channel.server.packet.S2C_TextMessagePacket import TextMessagePacket
from channel.server.packet.S2C_UserJoinPacket import UserJoinPacket
from channel.server.packet.S2C_UserLeavePacket import UserLeavePacket
from channel import Service


class ServerConnectionService(Service.ServiceThread):
    def __init__(self, paramClientAddress: tuple, paramConnection: socket.socket, paramChannelID: str,
                 paramServerPrivateKey: RSAPrivateKey, paramServerMaxUsers: int, paramServerUserList: list,
                 paramServerBanList: list):
        """
        Connect the client service
        :param paramClientAddress: (ip, port)
        :param paramConnection: Connection socket
        """
        super().__init__(Service.ServiceType.SERVER_CONNECTION)

        # General Server / User information
        self.__connection: socket.socket = paramConnection              # Socket connecting to client
        self.__clientAddress: tuple = paramClientAddress                # Client address (ip, port)
        self.__channelID: str = paramChannelID                          # Channel ID
        self.__serverPrivateKey: RSAPrivateKey = paramServerPrivateKey  # Server Private Key
        self.__lastAliveTime: int = int(time.time())                    # Last time client was alive

        # Obtained client information
        self.__displayName: str | None = None                  # Client display name
        self.__clientPublicKey: RSAPublicKey | None = None     # Client public key

        # Service flags
        self.__stop = Event()    # Stop event
        self.__ready = Event()   # Ready Event

        # Packet collector
        self.__packetCollector = PacketCollector(self.getConnection(), self.getServerPrivateKey(), self.getStopEvent())
        self.__packetCollector.start()

        # For server Authentication
        self.__serverMaxUsers: int = paramServerMaxUsers                            # Max number of users on the server
        self.__serverUserList: list[ServerConnectionService] = paramServerUserList  # List of of users on the server
        self.__serverBanList: list[str] = paramServerBanList                        # List of banned users on the server


    """
            Getter Methods
    """

    def getChannelID(self) -> str:
        """
        returns the client / server channel id
        :return: Channel ID for server / client (str)
        """
        return self.__channelID

    def getChannelIDHash(self) -> int:
        """
        returns the sha256 version of the server channel id as an int
        :return: sha256(channelID) (base 10)
        """
        hex_digest = hashlib.sha256(self.getChannelID().encode()).hexdigest()  # Convert the channel id to sha256
        return int(hex_digest, 16)  # Returns the int conversion of the hex digest

    def getMaxServerUsers(self) -> int:
        """
        Returns max number of server users
        :return: Number of user slots on the server
        """
        return self.__serverMaxUsers

    def getServerUserList(self) -> list:
        """
        Returns the list of users currently on the server
        :return: List of server users
        """
        return self.__serverUserList

    def getServerBanList(self) -> list:
        """
        Returns the list of users banned on the server
        :return: List of ips banned on the server
        """
        return self.__serverBanList

    """
            RSA
    """

    def getServerPrivateKey(self) -> RSAPrivateKey:
        """
        Get the server private key
        :return: The server private key (RSAPrivateKey)
        """
        return self.__serverPrivateKey

    def getServerPublicKey(self) -> RSAPublicKey:
        """
        Get the server public key
        :return: Server public key (RSAPublicKey)
        """
        return self.getServerPrivateKey().public_key()

    def setClientPublicKey(self, paramClientPublicKey: RSAPublicKey) -> None:
        """
        Set the client public key
        :param paramClientPublicKey: Client public key
        :return: None
        """
        self.__clientPublicKey = paramClientPublicKey

    def getClientPublicKey(self) -> RSAPublicKey:
        """
        Get the client's public key
        :return: The client's public key
        """
        return self.__clientPublicKey

    """
            Event Methods
    """

    def getReadyEvent(self) -> Event:
        """
        Returns the ready event
        :return:
        """
        return self.__ready

    def getStopEvent(self) -> Event:
        """
        returns the flag for the server connection being stopped
        :return: Stop flag (Event)
        """
        return self.__stop

    def stop(self) -> None:
        """
        Set the stop event
        :return: None
        """
        self.getStopEvent().set()


    """
            User
    """

    def registerUser(self) -> None:
        """
        Register as a user
        :return: None
        """
        assert self.getReadyEvent().is_set()

        self.getServerUserList().append(self)

        userJoinPacket = UserJoinPacket(self.getDisplayName())
        self.sendToAllRecipients(userJoinPacket)

    def unregisterUser(self) -> None:
        """
        Unregister as a user
        :return: None
        """
        self.getStopEvent().set()  # Set the stop flag
        if self in self.getServerUserList():  # Make sure the user is registered
            self.getServerUserList().remove(self)

        userLeavePacket = UserLeavePacket(self.getDisplayName())
        self.sendToAllRecipients(userLeavePacket)

    def setDisplayName(self, paramDisplayName: str) -> None:
        """
        Set the display name of the client
        :return: None
        """
        self.__displayName = paramDisplayName

    def getDisplayName(self) -> str:
        """
        Get the display name of the client
        :return: User display name (str)
        """
        return self.__displayName

    def getLastAliveTime(self) -> int:
        """
        Last time an alive signal was received from the client
        :return: Unix time (s)
        """
        return self.__lastAliveTime

    def renewTime(self) -> None:
        """
        Renews the time on the last alive time
        :return: None
        """
        self.__lastAliveTime = int(time.time())


    """
            Ban & Kick
    """

    def kickUser(self, paramReason: str | None) -> None:
        """
        Kicks user for specified reason or none
        :param paramReason: reason for kick
        :return: None
        """
        # Disconnect User
        clientDisconnectPacket = ClientDisconnectPacket(paramReason)
        self.sendPacket(clientDisconnectPacket)

        # Stop client connection
        self.stop()


    def banUser(self, paramReason: str | None):
        self.kickUser(paramReason)
        self.getServerBanList().append(self.getClientAddress()[0])



    """
            Packet Methods
    """

    def getPacketCollector(self) -> PacketCollector:
        """
        Returns the packet collector
        :return: Server / User packet collector
        """
        return self.__packetCollector

    def sendPacket(self, paramPacket: Packet) -> None:
        """
        Send a packet to the client
        :param paramPacket: The packet to send
        :return: None
        """
        if self.getReadyEvent().is_set():  # Check the client is ready to receive encrypted packets and
            # the server ready to send them
            sendPacket(paramPacket, (self.getConnection(), self.getClientPublicKey()))

    def sendToAllRecipients(self, paramPacket: Packet) -> None:
        """
        Send a packet to everyone on the server
        :param paramPacket:
        :return:
        """
        for connection in self.getServerUserList():  # Iterate over everyone in the server
            connection.sendPacket(paramPacket)

    def getConnection(self) -> socket.socket:
        """
        Get the connection socket
        :return: Connection socket
        """
        return self.__connection

    def getClientAddress(self) -> tuple:
        """
        Get the client address
        :return: tuple(ip, port)
        """
        return self.__clientAddress

    def sendInfoToUser(self, paramMessage: str) -> None:
        """
        Send an info packet to the client
        :param paramMessage: The message to send
        :return: None
        """
        infoMessagePacket = InfoMessagePacket(paramMessage)  # Construct the info message packet
        self.sendPacket(infoMessagePacket)  # Send the packet

    def authenticate(self) -> None:
        """
        Authenticate the server with the client
        :return: None
        """
        try:

            """ 1) Validate Client Authentication """
            # 1.1) Await packet and unpack it
            authenticatePacket = self.getPacketCollector().awaitPacket(packet_type=PacketType.C2S_AUTHENTICATE)
            if self.getStopEvent().is_set():
                return
            if authenticatePacket is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_COLLECT_PACKET)

            authenticate_packetType, authenticate_packetBin = authenticatePacket  # Unpack the packet

            # 1.2) Authenticate channel hash
            if authenticate_packetBin.getAttribute("CHANNEL_HASH") != self.getChannelIDHash():
                raise ServerException(self.getStopEvent(), ServerException.INVALID_CHANNEL_ID_HASH)

            # 1.3) Load the public key
            der_key_size = authenticate_packetBin.getAttribute("PUBLIC_KEY_LENGTH")
            der_key = authenticate_packetBin.getAttribute("CLIENT_PUBLIC_KEY").to_bytes(der_key_size, byteorder="big")

            client_public_key = serialization.load_der_public_key(
                der_key,
                backend=default_backend())

            # 1.4) Set the client public key
            self.setClientPublicKey(client_public_key)

            # 1.5) Encrypt the client challenge to the server
            clientEncryptedChallenge = self.getClientPublicKey().encrypt(
                # Concat the challenge with the the channel id in encrypted
                authenticate_packetBin.getAttributeBytes("CHALLENGE"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            """ 2) Send The Server Authenticate Packet To The Client """
            serverAuthenticatePacket = ServerAuthenticatePacket(self.getChannelID(),
                                                                self.getServerPublicKey(),
                                                                clientEncryptedChallenge)  # Construct the packet

            sendPacket(serverAuthenticatePacket, (self.getConnection(), None))  # Send the packet to client

            """ 3) Receive The Return Packet From The Client """
            # 3.1) Collect return packet
            authenticate_returnPacket = self.getPacketCollector()\
                .awaitPacket(packet_type=PacketType.C2S_AUTHENTICATE_RETURN)

            if self.getStopEvent().is_set():
                return

            # 3.2) Check if packet is valid
            if authenticate_returnPacket is None:
                raise ServerException(self.getStopEvent(), ServerException.MISSING_RETURN_PACKET)

            authenticate_return_packetType, authenticate_return_packetBin = authenticate_returnPacket  # Unpack packet

            # 3.3) Check the response hash
            if authenticate_return_packetBin.getAttribute("CHANNEL_HASH") != self.getChannelIDHash():
                raise ServerException(self.getStopEvent(), ServerException.INVALID_CHANNEL_ID_HASH)

            # 3.4) Check the decrypted challenge response
            decryptedClientChallenge = self.getServerPrivateKey().decrypt(
                authenticate_return_packetBin.getAttributeBytes("SIGNED_CHALLENGE"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 3.5) Check if client has successfully completed the challenge
            if decryptedClientChallenge != serverAuthenticatePacket.getChallenge() +\
                    self.getChannelID().encode('utf-8'):
                raise ServerException(self.getStopEvent(), ServerException.CLIENT_FAILED_CHALLENGE)

        except (ValueError, cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
            raise ServerException(self.getStopEvent(), ServerException.CRYPTOGRAPHY_EXCEPTION)

        except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
            raise ServerException(self.getStopEvent(), ServerException.SOCKET_EXCEPTION)

    def getUserData(self) -> None:
        """
        Gets and sets the user data
        :return: None
        """
        try:
            # 1) Send user data request
            serverRequestUserData = RequestUserData()  # Construct request user data packet
            sendPacket(serverRequestUserData, (self.getConnection(), self.getClientPublicKey()))  # Send packet

            # 2) Receive user data from client
            user_dataPacket = self.getPacketCollector().awaitPacket(packet_type=PacketType.C2S_USER_DATA)
            if self.getStopEvent().is_set():
                return

            if user_dataPacket is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_USER_DATA)

            userData_packetType, userData_packetBin = user_dataPacket  # Unpack packet

            encodedDisplayName = userData_packetBin.getAttributeBytes("DISPLAY_NAME")  # Display name
            if encodedDisplayName is None or len(encodedDisplayName) == 0:  # Check the display name
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_USER_DATA)
            displayName = ''.join([char for char in encodedDisplayName.decode()
                                   if char in LEGAL_DISPLAY_NAME_CHARACTERS])  # Strip any illegal characters

            # 3) Set the user display name
            self.setDisplayName(displayName[:min(len(displayName), CHANNEL_USER_DISPLAY_NAME_MAX)])

        except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
            raise ServerException(self.getStopEvent(), ServerException.SOCKET_EXCEPTION)

    def getClientServerErrors(self) -> list[str]:
        """
        Returns the list of reasons why client can't join the server
        :return: List of reasons why client can't join
        """
        userErrors = []  # Contains a list of all reasons why user can't join server

        if (len(self.getServerUserList()) + 1) > self.getMaxServerUsers():  # Check if server is full
            userErrors.append("Server is full!")

        if self.getConnection().getsockname()[0] in self.getServerBanList():  # Check if client is banned
            userErrors.append("You are banned from this channel!")

        for user in self.getServerUserList():
            if user.getDisplayName == self.getDisplayName():
                userErrors.append("Someone with that display name is already online!")
                break

        return userErrors  # Return all the errors

    def startListener(self):
        while not self.__stop.is_set():
            try:
                packet =  self.getPacketCollector().awaitPacket()  # Await a packet from client
                if self.getStopEvent().is_set():
                    return

                if packet is None:  # If packet is none then it will fail to collect packet
                    raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_COLLECT_PACKET)

                packetType, packetBin = packet  # Unpack packet

                match packetType:
                    case PacketType.C2S_ALIVE_RESPONSE:
                        self.renewTime()

                    case PacketType.C2S_USER_LEAVE:
                        return  # Return as the user has left

                    case PacketType.C2S_TEXT_MESSAGE:
                        encodedMessage = packetBin.getAttributeBytes("MESSAGE")
                        if encodedMessage is None:
                            continue

                        message = encodedMessage.decode('utf-8')
                        if len(message) > MAXIMUM_MESSAGE_SIZE:
                            self.sendInfoToUser(f"Message exceeds maximum size of: {MAXIMUM_MESSAGE_SIZE}")
                            continue

                        textMessagePacket = TextMessagePacket(self.getDisplayName(), message)
                        self.sendToAllRecipients(textMessagePacket)

            except (cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
                raise ServerException(self.getStopEvent(), ServerException.CRYPTOGRAPHY_EXCEPTION)

            except (socket.timeout, socket.error, ConnectionResetError):  # If a socket exception happens
                raise ServerException(self.getStopEvent(), ServerException.SOCKET_EXCEPTION)

    def run_safe(self):
        try:

            # 1) Authenticate and get public key
            self.authenticate()
            if self.getClientPublicKey() is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_CLIENT_PUBLIC_KEY)

            # 3) Get user info (just display name but expandable for later)
            self.getUserData()
            if self.getDisplayName() is None:
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_CLIENT_CREDENTIALS)

            # 4) Check if user passes checks i.e bans, and number of people online
            clientServer_errors = self.getClientServerErrors()

            if len(clientServer_errors) > 0:
                clientDisconnectPacket = ClientDisconnectPacket(", ".join(clientServer_errors))
                self.sendPacket(clientDisconnectPacket)
                raise ServerException(self.getStopEvent(), ServerException.CLIENT_REJECTED)

            # 5) Register user
            self.getReadyEvent().set()
            self.registerUser()

            self.startListener()

        finally:
            # 4) Close socket
            self.unregisterUser()
            self.getConnection().close()
