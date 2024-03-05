import random
import re
import hashlib
import string
from functools import lru_cache
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import socket
import time
from threading import Event
import base64

from Properties import CHANNEL_ID_LENGTH, CHANNEL_SECRET_KEY_LENGTH, DEFAULT_PORT_SERVER, CHANNEL_BIN_DIMENSIONS, \
    CHANNEL_INFO_BIN_DIMENSIONS, CHANNEL_USER_DISPLAY_NAME_MAX, ALIVE_TIME, MAXIMUM_MESSAGE_SIZE, IPType, \
    TERMINAL_PROTOCOL, DEFAULT_BAN_REASON, ALIVE_TIMEOUT, LEGAL_DISPLAY_NAME_CHARACTERS, TERMINAL_VERSION,\
    CHANNEL_BIN_INVALIDATE_DIMENSIONS
from channel.packet import Packet
import services.Service as Service
from utils.BinarySequencer import Bin, ArbitraryValue
from channel.packet.Packet import sendPacket, PacketType, PacketCollector
from channel.packet.server.S2C_AuthenticatePacket import ServerAuthenticatePacket
from channel.packet.server.S2C_RequestUserDataPacket import RequestUserData
from channel.packet.server.S2C_UserLeavePacket import UserLeavePacket
from channel.packet.server.S2C_UserJoinPacket import UserJoinPacket
from channel.packet.server.S2C_AlivePacket import AlivePacket
from channel.packet.server.S2C_InfoMessagePacket import InfoMessagePacket
from channel.packet.server.S2C_TextMessagePacket import TextMessagePacket
from channel.packet.server.S2C_ClientDisconnectPacket import ClientDisconnectPacket
from Language import info
from channel.MessengerExceptions import ServerException


class TerminalValidateService(Service.ServiceThread):
    def __init__(self, paramTerminalURL: str):
        """
        Validate the terminal
        :param paramTerminalURL:
        """
        super().__init__(Service.ServiceType.TERMINAL_VALIDATE)

        self.__terminalURL: str = paramTerminalURL
        self.__result: None | bool = None

    def getTerminalURL(self) -> str:
        """
        Get the terminal URL
        :return: terminal url (str)
        """
        return self.__terminalURL

    def getResult(self) -> bool:
        """
        Get the result value
        :return: result bool
        """
        return self.__result

    def validateTerminal(self) -> None:
        """
        Validate the terminal
        :return: None
        """
        try:
            response = requests.get(self.getTerminalURL() + "/status")
        except requests.RequestException:
            self.__result = False
            return

        # Check request has reached the terminal
        if response.status_code != 200:
            self.__result = False
            return

        # Check if it is a json response
        if response.headers.get('Content-Type') != "application/json":
            self.__result = False
            return

        try:
            responseJson = response.json()

            terminal, version = responseJson['version'].split(":")
            active = bool(responseJson['active'])

            self.__result = active and version == TERMINAL_VERSION and terminal == "TERMINAL"

        except (KeyError, ValueError, AttributeError):
            self.__result = False

    def run_safe(self):
        self.validateTerminal()


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
        assert self.getReadyEvent().is_set()

        self.getServerUserList().append(self)

        userJoinPacket = UserJoinPacket(self.getDisplayName())
        self.sendToAllRecipients(userJoinPacket)

    def unregisterUser(self) -> None:
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

        except (cryptography.exceptions.NotYetFinalized, cryptography.exceptions.InvalidKey):
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


class ServerAliveService(Service.ServiceThread):
    def __init__(self, paramServerUserList: list[ServerConnectionService], paramStopEvent: Event):
        """
        Server Alive Service to check nobody has timed out or disconnected missing a packet
        :param paramServerUserList:
        """
        super().__init__(Service.ServiceType.SERVER_ALIVE)

        self.__stop = paramStopEvent
        self.__serverUserList = paramServerUserList

    def getServerUserList(self) -> list[ServerConnectionService]:
        """
        Returns the server user list
        :return:
        """
        return self.__serverUserList

    def getStopEvent(self) -> Event:
        """
        Get the stop event
        :return: The stop event
        """
        return self.__stop

    def stop(self) -> None:
        """
        Stop the service
        :return: None
        """
        self.getStopEvent().set()

    def run_safe(self):
        alivePacket = AlivePacket()  # Create an alive packet

        while not self.getStopEvent().is_set():  # Run until the stop flag is set
            start_currentTime = int(time.time())  # Get the current time

            for user in self.getServerUserList():  # Get each user connected
                if user.getLastAliveTime() + ALIVE_TIMEOUT < start_currentTime:
                    user.kickUser("Timed out.")  # Time out if the last alive time was too long away
                    continue
                user.sendPacket(alivePacket)

            difference_currentTime: int = int(time.time()) - start_currentTime  # Get the difference in times
            self.getStopEvent().wait(ALIVE_TIME - difference_currentTime)  # Wait for the next cycle


class ServerHostService(Service.ServiceThread):
    def __init__(self, paramServerPort: int, paramStopEvent: Event,
                 paramChannelID: str, paramServerPrivateKey: RSAPrivateKey, paramServerMaxUsers: int,
                 paramServerUserList: list, paramServerBanList: list):
        super().__init__(Service.ServiceType.SERVER_HOST)

        self.__serverPort = paramServerPort  # Port the server is running on
        self.__stop = paramStopEvent  # Server stop event

        self.__channelID: str = paramChannelID  # Channel ID
        self.__serverPrivateKey: RSAPrivateKey = paramServerPrivateKey  # Server Private Key

        # For server Authentication
        self.__serverMaxUsers: int = paramServerMaxUsers  # Max number of users on the server
        self.__serverUserList: list[ServerConnectionService] = paramServerUserList  # List of of users on the server
        self.__serverBanList: list[str] = paramServerBanList  # List of banned users on the server

        self.__ready = Event()

    def getServerPort(self) -> int:
        """
        Returns the server port
        :return: The server port
        """
        return self.__serverPort

    def getStopEvent(self) -> Event:
        """
        Get the stop event
        :return: The stop event
        """
        return self.__stop

    def getReadyEvent(self) -> Event:
        """
        Ready Event for the host service
        :return: The ready event
        """
        return self.__ready

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

    def getServerPrivateKey(self) -> RSAPrivateKey:
        """
        Returns the server private key
        :return: Server private key (RSAPrivateKey)
        """
        return self.__serverPrivateKey

    def getChannelID(self) -> str:
        """
        Gets the server channel id
        :return:
        """
        return self.__channelID

    def run_safe(self):
        host = socket.gethostname()
        port = self.getServerPort()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            try:
                server_socket.bind((host, port))
            except OSError:
                raise ServerException(self.getStopEvent(), ServerException.SERVER_ALREADY_ON_PORT)
            self.getReadyEvent().set()

            server_socket.listen()
            server_socket.settimeout(1.0)

            while not self.getStopEvent().is_set():
                try:
                    # Accept new connection
                    connection, client_address = server_socket.accept()

                    # Create a new server connection
                    serverConnectionService = ServerConnectionService(client_address, connection,
                                                                      self.getChannelID(),
                                                                      self.getServerPrivateKey(),
                                                                      self.getMaxServerUsers(),
                                                                      self.getServerUserList(),
                                                                      self.getServerBanList())

                    serverConnectionService.start()
                except socket.timeout:
                    pass  # Refresh the stop event flag

            server_socket.close()


class PublishChannelService(Service.ServiceThread):
    def __init__(self, paramStopEvent: Event, paramTerminal: str, paramChannelID: str,
                 paramIsPublic: bool, paramChannelBin: Bin):
        """
        Method to publish channel to the terminal
        :param paramStopEvent: Server stop event
        :param paramTerminal: Server terminal url
        :param paramChannelID: Server channel ID
        :param paramIsPublic: Server public setting
        :param paramChannelBin: Server channel bin
        """
        super().__init__(Service.ServiceType.SERVER_PUBLISH)

        self.__channelBin: Bin = paramChannelBin
        self.__stopEvent: Event = paramStopEvent
        self.__terminal: str = paramTerminal
        self.__channelID: str = paramChannelID
        self.__isPublic: bool = paramIsPublic
        self.__result: dict | None = None

    """
            Getter Methods
    """

    def getTerminal(self) -> str:
        """
        Returns the terminal url
        :return: Terminal URL server is using (str)
        """
        return self.__terminal

    def getChannelBin(self) -> Bin:
        """
        Returns the channel bin
        :return: Channel Bin
        """
        return self.__channelBin

    def isPublic(self) -> bool:
        """
        Returns if the server is public
        :return: If the server is public
        """
        return self.__isPublic

    def getChannelID(self) -> str:
        """
        Returns the channel ID
        :return: Channel ID
        """
        return self.__channelID

    def getStopEvent(self) -> Event:
        """
        Returns the stop event
        :return: Stop event
        """
        return self.__stopEvent

    def getResult(self) -> dict:
        """
        Returns the result of the channel bin
        :return: Result of validating
        """
        return self.__result

    """
            Methods
    """

    def publish(self) -> None:
        """
        Attempts to publish the channel to the terminal and saves value in result
        :return: None
        """

        channelBinBytes = self.getChannelBin().getResultBytes()

        try:
            json = {
                "CHANNEL_BYTES": base64.b64encode(channelBinBytes).decode('utf-8')
            }

            if self.isPublic():
                json["CHANNEL_ID"] = self.getChannelID()

            response = requests.post(f"{self.getTerminal()}/validate", json=json)  # Send validation post request

            self.__result = response.json()

        except (requests.RequestException, requests.exceptions.ContentDecodingError):
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_PUBLISH_CHANNEL)

    def run_safe(self):
        self.publish()


class UnPublishChannelService(Service.ServiceThread):
    def __init__(self, paramStopEvent: Event, paramTerminal: str, paramChannelBin: Bin ):
        """
        Method to unpublish channel
        :param paramTerminal: Server terminal
        :param paramStopEvent: Server stop event
        """
        super().__init__(Service.ServiceType.SERVER_UNPUBLISH)

        self.__terminal: str = paramTerminal
        self.__stopEvent: Event = paramStopEvent
        self.__channelBin: Bin = paramChannelBin
        self.__result: dict | None = None

    """
            Getter Methods
    """

    def getTerminal(self) -> str:
        """
        Returns the terminal url
        :return: Terminal URL server is using (str)
        """
        return self.__terminal

    def getChannelBin(self) -> Bin:
        """
        Returns the channel bin
        :return: Channel Bin
        """
        return self.__channelBin

    def getStopEvent(self) -> Event:
        """
        Returns the stop event
        :return: Stop event
        """
        return self.__stopEvent

    def getResult(self) -> dict:
        """
        Returns the result of the channel bin
        :return: Result of validating
        """
        return self.__result

    """
            Methods
    """

    def unpublish(self) -> None:
        """
        Attempts to unpublish channel in terminal and saves result
        :return:
        """

        try:

            channelBinBytes = self.getChannelBin().getResultBytes()

            json = {
                "CHANNEL_BYTES": base64.b64encode(channelBinBytes).decode('utf-8')
            }

            response = requests.post(f"{self.getTerminal()}/unvalidate", json=json)

            self.__result = response.json()

        except (requests.RequestException, requests.exceptions.ContentDecodingError):
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_UNPUBLISH_CHANNEL)

    def run_safe(self):
        self.unpublish()


class Server:
    def __init__(self, paramServerTerminal: str, channel_id=None, secret_key=None, port=DEFAULT_PORT_SERVER,
                 tunnel_url=None, public=False, max_users=20, banned_users=None):

        # Validate that the server terminal starts with an accepted protocol
        if not any([paramServerTerminal.startswith(protocol) for protocol in TERMINAL_PROTOCOL]):
            raise ServerException(None, ServerException.INVALID_TERMINAL_URL)

        # Server address
        self.__terminal: str = paramServerTerminal
        self.__port: int = port
        self.__tunnelURL: dict | None = tunnel_url

        # Server Channel
        self.__channelID: str = channel_id if channel_id is not None else generateRandomChannelID()
        self.__secretKey: str = secret_key if secret_key is not None else generateRandomSecretKey()
        self.__public: bool = public

        # RSA
        self.__privateKey: RSAPrivateKey | None = None
        self.generatePublicAndPrivateKeys()

        # User Management
        self.__userList: list[ServerConnectionService] = []
        self.__bannedUsers: list[str] = [] if banned_users is None else banned_users
        self.__maxNumberOfUsers: int = max_users


        # Events
        self.__stop: Event = Event()
        self.__ready: Event = Event()

        # Services
        self.__serverHostService: ServerHostService | None = None
        self.__serverAliveService: ServerAliveService | None = None

        self.startServer()

    """
            Getter Methods
    """

    def getTerminal(self) -> str:
        """
        Returns the terminal being used
        :return: Terminal URL (str)
        """
        return self.__terminal

    def getChannelID(self) -> str:
        """
        Returns the channel ID of the server
        :return: Channel ID (str)
        """
        return self.__channelID

    def getSecretKey(self) -> str:
        """
        Returns the secret key of the server
        :return: Secret key of server (str)
        """
        return self.__secretKey

    def getPort(self) -> int:
        """
        Returns the server port
        :return: Server port (int)
        """
        return self.__port

    def isPublic(self) -> bool:
        """
        Returns if the server is shown as public on the terminal
        :return: Server shown (bool)
        """
        return self.__public

    """
                Events
    """

    def getReadyEvent(self) -> Event:
        """
        Returns the ready event
        :return: Stop flag (Event)
        """
        return self.__ready

    def getStopEvent(self) -> Event:
        """
        returns the flag for the server being stopped
        :return: Stop flag (Event)
        """
        return self.__stop

    """
                IP
    """

    @lru_cache(maxsize=1)
    def getIP(self) -> dict:
        """
        Returns the ip in all different forms
        :return:
        """

        response = requests.get("https://httpbin.org/ip")  # Makes a request to find the external ip

        if response.status_code != 200:  # Check that the request is OK
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_GET_IP)

        ip = response.json()['origin']  # Read the IP from the website

        # Bundles up the ip

        # Check if IP is 0: v4 or 1: v6 and return it in binary
        if "." in ip:
            return {"internal_ip": '127.0.0.1',
                    "ip_type": IPType.IPv4,
                    "ip": ip,
                    "ip_binary": int(''.join([bin(int(split))[2:].zfill(8) for split in ip.split(".")]), 2)
                    }

        elif ":" in ip:
            return {"internal_ip": '127.0.0.1',
                    "ip_type": IPType.IPv6,
                    "ip": ip,
                    "ip_binary": int(''.join([bin(int(split, 16))[2:].zfill(16) for split in ip.split(":")]), 2)
                    }

    """
            Tunneling
    """

    def isTunneling(self) -> bool:
        """
        Returns if the server is tunneling
        :return: Server is tunneling (bool)
        """
        return self.__tunnelURL is not None

    def getTunnelURL(self) -> dict:
        """
        Returns the tunnel url
        :return: tunnel url {http(s)://..., port}
        """
        return self.__tunnelURL

    def setTunnelURL(self, paramTunnelURL: dict):
        """
        Sets the tunnel url
        :param paramTunnelURL: tunnel url {http(s)://..., port}
        :return:
        """
        self.__tunnelURL = paramTunnelURL

    """
            Services
    """

    def getServerHostService(self) -> ServerHostService:
        """
        Returns the host service
        :return: Host service
        """
        return self.__serverHostService

    def getServerAliveService(self) -> ServerAliveService:
        """
        Returns the alive service
        :return:
        """
        return self.__serverAliveService

    """
            Server Connection Service
    """

    def getUserByDisplayName(self, paramDisplayName: str) -> ServerConnectionService:
        """
        Gets the Server Connection Service by their display name
        :param paramDisplayName: Display name searched for
        :return: client connections
        """
        for serverConnectionService in self.getUserList():
            if serverConnectionService.getDisplayName() == paramDisplayName:
                return serverConnectionService

        raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_FIND_USER)

    def getMaxNumberOfUsers(self) -> int:
        """
        Returns the max number of users on the server
        :return: Max number of users on the server
        """
        return self.__maxNumberOfUsers

    def setMaxNumberOfUsers(self, paramNumberOfUsers) -> None:
        """
        Set the max number of users on the server
        :param paramNumberOfUsers: Max number of clients
        :return: None
        """
        self.__maxNumberOfUsers = paramNumberOfUsers

    def getUserList(self) -> list[ServerConnectionService]:
        """
        Returns the list of users on the server
        :return: List of server users
        """
        return self.__userList


    def getNumberOfUsers(self) -> int:
        """
        Gets the number of users
        :return: Number of users
        """
        return len(self.getUserList())

    def getBannedUsers(self) -> list[str]:
        """
        Returns a list of banned IPs
        :return:
        """
        return self.__bannedUsers

    def banUser(self, paramDisplayName: str, paramReason=DEFAULT_BAN_REASON):
        """
        Bans a user
        :param paramReason: Reason for ban
        :param paramDisplayName: Display name of user to ban
        """
        client = self.getUserByDisplayName(paramDisplayName)
        client.banUser(paramReason)

    def kickUser(self, paramDisplayName: str, paramReason: str):
        """
        Kicks a user from the server
        :param paramDisplayName: Display name of user to kick
        :param paramReason: Reason for kick
        :return:
        """
        client = self.getUserByDisplayName(paramDisplayName)
        client.kickUser(paramReason)

    def kickAllUsers(self, disconnect_reason=None):
        """
        Kicks all users from the server
        :param disconnect_reason:
        :return:
        """
        for key in self.getUserList()[:]:  # Duplicate user list to avoid problems
            key.kickUser(disconnect_reason)

    """
                RSA
    """

    def getServerPrivateKey(self) -> RSAPrivateKey:
        """
        Returns the Server Private Key
        :return: Server Private Key (RSAPrivateKey)
        """
        return self.__privateKey

    def getServerPublicKey(self) -> RSAPublicKey:
        """
        Returns the Server Public Key
        :return: Server Public Key
        """
        return self.getServerPrivateKey().public_key()

    def generatePublicAndPrivateKeys(self) -> None:
        """
        Generates the public and private keys
        :return: None
        """
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # The size of the key in bits
        )

        self.__privateKey = private_key

    """
                SERVER
    """

    def stopServer(self):
        # Start unvalidate service in terminal
        unpublishService = UnPublishChannelService(self.getStopEvent(), self.getTerminal(),
                                                   createUnvalidateChannelBin(self))
        unpublishService.start()

        # Kick all users
        self.kickAllUsers("Server stopping.")
        self.getStopEvent().set()

        self.getServerAliveService().join()
        self.getServerHostService().join()

        # Wait for the host service to finish
        info("CHANNEL_CLOSE", terminal=self.getTerminal(), channel_id=self.getChannelID(),
             secret_key=self.getSecretKey(), ip=self.getIP().get("ip"),
             port=str(self.getPort()), public=str(self.isPublic()))

        # Wait for all to finish
        unpublishService.join()
        if not unpublishService.getResult()['SUCCESS']:  # Check if successfully unpublished channel
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_UNPUBLISH_CHANNEL)


    def startServer(self):
        # 1) Check if terminal is available
        terminalValidateService = TerminalValidateService(self.getTerminal())
        terminalValidateService.start()
        terminalValidateService.join()

        if not terminalValidateService.getResult():
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_VALIDATE_TERMINAL)

        # 2) Start receiver thread

        serverHostService = ServerHostService(self.getPort(), self.getStopEvent(), self.getChannelID(),
                                              self.getServerPrivateKey(), self.getMaxNumberOfUsers(),
                                              self.getUserList(), self.getBannedUsers())

        serverHostService.start()  # Start the host service
        self.__serverHostService = serverHostService

        # Wait for it to start or if it doesnt then return an error
        while True:
            if serverHostService.getReadyEvent().is_set():
                break
            if self.getStopEvent().is_set():
                raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_START_HOST_SERVICE)

        # 2.1) Send message after service is ready
        info("CHANNEL_CREATE", terminal=self.getTerminal(), channel_id=self.getChannelID(),
             secret_key=self.getSecretKey(), ip=self.getIP().get("ip"),
             port=str(self.getPort()), public=str(self.isPublic()))

        # 3) Start alive service

        serverAliveService = ServerAliveService(self.getUserList(), self.getStopEvent())
        serverAliveService.start()
        self.__serverAliveService = serverAliveService

        # 4) Publish channel public service

        publishChannelService = PublishChannelService(self.getStopEvent(), self.getTerminal(), self.getChannelID(),
                                                      self.isPublic(), createValidateChannelBin(self))
        publishChannelService.start()
        publishChannelService.join()

        if not publishChannelService.getResult()['SUCCESS']:
            raise ServerException(self.getStopEvent(), ServerException.FAILED_TO_PUBLISH_CHANNEL)


def generateRandomSequence(length: tuple | int) -> str:
    """
    Generate a random sequence containing hyphens to split text
    :param length:
    :return:
    """
    if isinstance(length, tuple):
        length = random.randint(length[0],
                                length[1])

    assert isinstance(length, int)

    # Don't use " " or "-" from base64 alphabet for channel ID
    randomCharacterArray = random.choices(re.sub('[- ]', '', string.ascii_letters), k=length)
    numberOfHyphens = len(randomCharacterArray) // 4

    # Run through the string to insert hyphens
    for index in range(numberOfHyphens // 2):
        for hyphenLocation in [(index + 1) * numberOfHyphens,
                               len(randomCharacterArray) - ((index + 1) * numberOfHyphens)]:
            if not (index + 1) * numberOfHyphens:  # Avoid indexing 0
                continue

            if (hyphenLocation - 1 >= 0 and randomCharacterArray[hyphenLocation - 1] != '-') and \
                    (hyphenLocation + 1 < len(randomCharacterArray) and randomCharacterArray[
                        hyphenLocation + 1] != '-'):
                randomCharacterArray[hyphenLocation] = '-'

    return "".join(randomCharacterArray)


def generateRandomChannelID(length=CHANNEL_ID_LENGTH) -> str:
    """
    Generate a random channel ID
    :param length:
    :return:
    """
    return generateRandomSequence(length)


def generateRandomSecretKey(length=CHANNEL_SECRET_KEY_LENGTH) -> str:
    """
    Generate a random channel secret key
    :param length:
    :return:
    """
    return generateRandomSequence(length)


def xorRing(value0: int, value1: int) -> int:
    """
    XOR Ring two ints
    :param value0: int1
    :param value1: int2
    :return: xor result
    """
    return value0 ^ value1


def generateAuthenticationID(paramAuthSum) -> list[int]:
    """
    Generates an authentication sequence
    :param paramAuthSum:
    :return:
    """
    return [authCount := paramAuthSum - random.randint(0, paramAuthSum), paramAuthSum - authCount]


def createChannelInfoBin(paramServer: Server) -> Bin:
    """
    Creates the channel info bin
    :param paramServer: Server
    :return: Channel info bin
    """
    channelInfoBin = Bin(CHANNEL_INFO_BIN_DIMENSIONS)

    # UNIQUE AUTH
    authentication_sum = (2 ** ((channelInfoBin.getAttributeSize("UNIQUE_AUTH_HI")
                                 + channelInfoBin.getAttributeSize("UNIQUE_AUTH_LO"))
                                // 2)) - 1
    authentication_hi, authentication_lo = generateAuthenticationID(authentication_sum)

    channelInfoBin.setAttribute("UNIQUE_AUTH_HI", authentication_hi)
    channelInfoBin.setAttribute("UNIQUE_AUTH_LO", authentication_hi)

    ip_attribute_size = channelInfoBin.getAttributeSize("IP")

    if paramServer.isTunneling():

        channelInfoBin.setAttribute("IP_TYPE", 2)

        ip_length_bits = len(paramServer.getTunnelURL().get("tunnel_url")) * 8
        ip_length = ip_length_bits + (ip_length_bits % 8)

        assert ip_length <= ip_attribute_size

        placement = ip_attribute_size - ip_length
        channelInfoBin.setAttribute("IP_PLACEMENT", placement)

        ip_bin = Bin([("A", placement, ArbitraryValue.RANDOMISE),
                      ("IP", ip_length, paramServer.getTunnelURL().get("tunnel_binary"))])

    else:
        ip_data = paramServer.getIP()

        match ip_data.get("ip_type"):
            case IPType.IPv4:
                channelInfoBin.setAttribute("IP_TYPE", 0)

                placement = random.randint(0, ip_attribute_size - 32)

                ip_bin = Bin([("A", placement, ArbitraryValue.RANDOMISE),
                              ("IP", 32, ip_data.get("ip_binary")),
                              ("Z", ip_attribute_size - placement - 32, ArbitraryValue.RANDOMISE)])

            case IPType.IPv6:
                channelInfoBin.setAttribute("IP_TYPE", 1)

                placement = random.randint(0, ip_attribute_size - 128)
                channelInfoBin.setAttribute("IP_PLACEMENT", placement)

                ip_bin = Bin([("A", placement, ArbitraryValue.RANDOMISE),
                              ("IP", 128, ip_data.get("ip_binary")),
                              ("Z", ip_attribute_size - placement - 128, ArbitraryValue.RANDOMISE)])
            case _:
                raise ServerException(None, ServerException.INVALID_IP_FORMAT)

    channelInfoBin.setAttribute("IP_PLACEMENT", placement)

    assert ip_bin.getBinSize() == channelInfoBin.getAttributeSize("IP")
    channelInfoBin.setAttribute("IP", ip_bin.getResult())


    channelInfoBin.setAttribute("PORT", paramServer.getPort())

    return channelInfoBin


def createValidateChannelBin(paramServer: Server) -> Bin:
    """
    Creates the channel info bin and then adds xor rings
    :param paramServer:
    :return:
    """
    channelBin = Bin(CHANNEL_BIN_DIMENSIONS)

    # Channel Info Bin
    channelNameHash = hashlib.sha512(paramServer.getChannelID().encode()).hexdigest()
    channelInfoBinXOR = xorRing(int(channelNameHash, 16), createChannelInfoBin(paramServer).getResult())
    channelBin.setAttribute("CHANNEL_INFO_BIN", channelInfoBinXOR)

    # Channel Secret Bin
    secretKeyHash = hashlib.sha256(paramServer.getSecretKey().encode()).hexdigest()
    secretKey = int(secretKeyHash, 16)
    channelBin.setAttribute("CHANNEL_SECRET_BIN", secretKey)

    return channelBin


def createUnvalidateChannelBin(paramServer: Server) -> Bin:
    """
    Creates the unvalidate channel bin info
    :param paramServer:
    :return:
    """

    unvalidateChannelBin = Bin(CHANNEL_BIN_INVALIDATE_DIMENSIONS)

    channelBin: Bin = createValidateChannelBin(paramServer)
    infoBin: Bin = Bin(CHANNEL_INFO_BIN_DIMENSIONS, population=channelBin.getAttribute("CHANNEL_INFO_BIN"))

    # Set secret key
    unvalidateChannelBin.setAttribute("CHANNEL_SECRET_BIN", channelBin.getAttribute("CHANNEL_SECRET_BIN"))
    unvalidateChannelBin.setAttribute("UNIQUE_AUTH_HI", infoBin.getAttribute("UNIQUE_AUTH_HI"))
    unvalidateChannelBin.setAttribute("UNIQUE_AUTH_LO", infoBin.getAttribute("UNIQUE_AUTH_LO"))

    return unvalidateChannelBin
